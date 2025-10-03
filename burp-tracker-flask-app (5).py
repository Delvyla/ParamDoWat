from flask import Flask, render_template, request, jsonify
from bs4 import BeautifulSoup
from collections import defaultdict

app = Flask(__name__)

# Auto-tagging patterns
AUTO_TAG_PATTERNS = {
    'File Upload': ['file', 'upload', 'document', 'doc', 'attachment', 'image', 'photo', 'pdf'],
    'IDOR': ['id', 'user', 'account', 'profile', 'uid', 'userid', 'accountid'],
    'XSS': ['search', 'query', 'q', 'keyword', 'message', 'comment', 'text', 'content'],
    'SQLi': ['id', 'sort', 'order', 'filter', 'category', 'type'],
    'Auth': ['token', 'session', 'auth', 'key', 'api', 'secret', 'password', 'login'],
    'Redirect': ['redirect', 'url', 'return', 'next', 'callback', 'continue', 'returnurl'],
    'Path Traversal': ['path', 'dir', 'folder', 'directory', 'file', 'filename'],
    'Admin': ['admin', 'role', 'privilege', 'permission', 'access', 'level'],
    'Debug': ['debug', 'test', 'dev', 'trace', 'verbose', 'log']
}

def get_auto_tags(param_name):
    """Get auto tags for a parameter"""
    tags = []
    lower_name = param_name.lower()
    for tag, patterns in AUTO_TAG_PATTERNS.items():
        if any(pattern in lower_name for pattern in patterns):
            tags.append(tag)
    return tags

def parse_burp_html(html_content):
    """Parse Burp Suite HTML export - only Dynamic URLs section"""
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Find the Dynamic URLs section
    dynamic_header = None
    for h2 in soup.find_all('h2'):
        if 'Dynamic URLs' in h2.get_text():
            dynamic_header = h2
            break
    
    if not dynamic_header:
        return []
    
    # Find the next h2 (like "Static URLs") to know where to stop
    next_header = dynamic_header.find_next_sibling('h2')
    
    # Get the ul after Dynamic URLs
    main_ul = dynamic_header.find_next_sibling('ul')
    
    if not main_ul:
        return []
    
    # If there's another h2 after Dynamic URLs, remove everything from that point onwards
    if next_header:
        # Remove all siblings after the next h2 (and the h2 itself)
        for sibling in list(next_header.next_siblings):
            if hasattr(sibling, 'extract'):
                sibling.extract()
        next_header.extract()
    
    urls = []
    
    # Now parse the cleaned ul
    for li in main_ul.find_all('li', recursive=False):
        url_text = li.find(text=True, recursive=False)
        if url_text:
            url_text = url_text.strip()
        
        if not url_text or not url_text.startswith('http'):
            continue
        
        current_url = {
            'url': url_text,
            'parameters': []
        }
        
        # Find nested ul with parameters
        nested_ul = li.find('ul')
        if nested_ul:
            for param_li in nested_ul.find_all('li'):
                param_text = param_li.get_text(strip=True)
                if param_text and '=' in param_text:
                    key, value = param_text.split('=', 1)
                    current_url['parameters'].append({
                        'key': key.strip(),
                        'value': value.strip()
                    })
                elif param_text:
                    current_url['parameters'].append({
                        'key': param_text.strip(),
                        'value': ''
                    })
        
        if current_url['parameters']:
            urls.append(current_url)
    
    return urls
    
def process_urls(urls):
    """Process URLs into parameter data structure"""
    param_data = {}
    all_params = set()
    
    for url_obj in urls:
        for param in url_obj['parameters']:
            key = param['key']
            all_params.add(key)
            
            if key not in param_data:
                param_data[key] = {
                    'values': {},
                    'total_occurrences': 0,
                    'auto_tags': get_auto_tags(key)
                }
            
            value = param['value'] if param['value'] else '(empty)'
            if value not in param_data[key]['values']:
                param_data[key]['values'][value] = []
            
            param_data[key]['values'][value].append(url_obj['url'])
            param_data[key]['total_occurrences'] += 1
    
    # Sort parameters by occurrence count (highest first), then alphabetically
    sorted_params = sorted(
        list(all_params),
        key=lambda p: (-param_data[p]['total_occurrences'], p)
    )
    
    return {
        'params': param_data,
        'all_param_names': sorted_params,
        'total_urls': len(urls),
        'total_params': len(all_params)
    }

def get_co_occurrence(urls, target_param):
    """Calculate parameter co-occurrence"""
    co_occurrence = defaultdict(int)
    
    for url_obj in urls:
        param_keys = [p['key'] for p in url_obj['parameters']]
        if target_param in param_keys:
            for key in param_keys:
                if key != target_param:
                    co_occurrence[key] += 1
    
    result = []
    for param, count in sorted(co_occurrence.items(), key=lambda x: x[1], reverse=True)[:10]:
        result.append({
            'param': param,
            'count': count,
            'auto_tags': get_auto_tags(param)
        })
    
    return result

# Store data in memory (you could use Redis or DB for production)
app_data = {
    'urls': [],
    'processed': None
}

@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    """Handle file upload and parsing"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    html_content = file.read().decode('utf-8')
    file_size = len(html_content) / (1024 * 1024)
    
    # Parse HTML
    urls = parse_burp_html(html_content)
    
    # Process data
    processed = process_urls(urls)
    
    # Store in memory
    app_data['urls'] = urls
    app_data['processed'] = processed
    
    return jsonify({
        'success': True,
        'file_size': round(file_size, 2),
        'data': processed
    })

@app.route('/api/parameter/<param_name>')
def get_parameter_details(param_name):
    """Get details for a specific parameter"""
    if not app_data['processed']:
        return jsonify({'error': 'No data loaded'}), 400
    
    if param_name not in app_data['processed']['params']:
        return jsonify({'error': 'Parameter not found'}), 404
    
    return jsonify({
        'param': param_name,
        'data': app_data['processed']['params'][param_name]
    })

@app.route('/api/relationships/<param_name>')
def get_relationships(param_name):
    """Get parameter relationships"""
    if not app_data['urls']:
        return jsonify({'error': 'No data loaded'}), 400
    
    relationships = get_co_occurrence(app_data['urls'], param_name)
    
    return jsonify({
        'param': param_name,
        'relationships': relationships
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
