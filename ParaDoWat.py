from flask import Flask, render_template, request, jsonify
from bs4 import BeautifulSoup
from collections import defaultdict
import subprocess
import tempfile
import os

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
    """Parse cleaned Burp Suite HTML"""
    soup = BeautifulSoup(html_content, 'html.parser')
    
    main_ul = soup.find('ul')
    if not main_ul:
        return []
    
    urls = []
    current_url = None
    
    for child in main_ul.children:
        if not hasattr(child, 'name'):
            continue
            
        if child.name == 'li':
            url_text = child.get_text(strip=True)
            if url_text.startswith('http'):
                current_url = {
                    'url': url_text,
                    'parameters': []
                }
                urls.append(current_url)
        elif child.name == 'ul' and current_url:
            for param_li in child.find_all('li'):
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
    
    return [u for u in urls if u['parameters']]

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
                    'auto_tags': get_auto_tags(key),
                    'has_empty_values': False
                }
            
            value = param['value'] if param['value'] else '(empty)'
            if value not in param_data[key]['values']:
                param_data[key]['values'][value] = []
            
            # Track if parameter has empty values
            if not param['value']:
                param_data[key]['has_empty_values'] = True
            
            param_data[key]['values'][value].append(url_obj['url'])
            param_data[key]['total_occurrences'] += 1
    
    # Sort parameters with priority:
    # 1. Most appeared parameters with most attack tags first
    # 2. Other most appeared parameters
    # 3. Parameters with values
    # 4. Parameters with empty values last
    def sort_key(param_name):
        data = param_data[param_name]
        num_tags = len(data['auto_tags'])
        occurrences = data['total_occurrences']
        has_values = not data['has_empty_values'] or len(data['values']) > 1
        
        # Return tuple for sorting (higher priority = lower numbers)
        # Priority 1: Parameters with tags and high occurrences (negative for descending)
        # Priority 2: High occurrences (negative for descending)
        # Priority 3: Has non-empty values (0 = has values, 1 = only empty)
        # Priority 4: Alphabetical
        return (
            -occurrences,       # More occurrences = higher priority
            -num_tags,  # Attack tags first (more tags = higher priority)                
            0 if has_values else 1,             # Has values before empty-only
            param_name                          # Alphabetical as tiebreaker
        )
    
    sorted_params = sorted(list(all_params), key=sort_key)
    
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

# Store data in memory
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
    
    # Read file as bytes
    file_bytes = file.read()
    
    # Save to temporary file
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.html', delete=False) as temp_input:
        temp_input.write(file_bytes)
        temp_input_path = temp_input.name
    
    # Create temp output file
    temp_output = tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False)
    temp_output_path = temp_output.name
    temp_output.close()
    
    try:
        # Call standalone extraction script
        print(f"Calling extraction script: {temp_input_path} -> {temp_output_path}")
        result = subprocess.run(
            ['python', 'extract_dynamic_urls.py', temp_input_path, temp_output_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        print(f"Return code: {result.returncode}")
        print(f"STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")
        
        if result.returncode != 0:
            return jsonify({'error': f'Extraction failed: {result.stderr}'}), 400
        
        # Read cleaned HTML
        with open(temp_output_path, 'r', encoding='utf-8') as f:
            cleaned_html = f.read()
        
        print(f"Cleaned HTML length: {len(cleaned_html)}")
        
        file_size = len(cleaned_html) / (1024 * 1024)
        
        # Parse
        urls = parse_burp_html(cleaned_html)
        print(f"Parsed {len(urls)} URLs")
        
        processed = process_urls(urls)
        print(f"Processed {processed['total_params']} parameters")
        
        # Store
        app_data['urls'] = urls
        app_data['processed'] = processed
        
        return jsonify({
            'success': True,
            'file_size': round(file_size, 2),
            'data': processed
        })
        
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Extraction timed out'}), 500
    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}), 500
    finally:
        # Cleanup
        try:
            os.unlink(temp_input_path)
            os.unlink(temp_output_path)
        except:
            pass

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
