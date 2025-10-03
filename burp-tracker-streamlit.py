import streamlit as st
from bs4 import BeautifulSoup
from collections import defaultdict
import pandas as pd

# Page config
st.set_page_config(
    page_title="Burp Parameter Tracker",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

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
    """Get auto tags for a parameter based on patterns"""
    tags = []
    lower_name = param_name.lower()
    for tag, patterns in AUTO_TAG_PATTERNS.items():
        if any(pattern in lower_name for pattern in patterns):
            tags.append(tag)
    return tags

def parse_burp_html(html_content):
    """Parse Burp Suite HTML export"""
    soup = BeautifulSoup(html_content, 'html.parser')
    
    urls = []
    main_ul = soup.find('body').find('ul')
    
    if not main_ul:
        return []
    
    children = list(main_ul.children)
    current_url = None
    
    for child in children:
        if child.name == 'li':
            url_text = child.get_text(strip=True)
            if url_text.startswith('http'):
                current_url = {
                    'url': url_text,
                    'parameters': []
                }
                urls.append(current_url)
        elif child.name == 'ul' and current_url is not None:
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
    
    # Filter out URLs with no parameters
    urls = [u for u in urls if u['parameters']]
    
    return urls

def get_parameter_data(urls):
    """Extract parameter information from URLs"""
    param_data = defaultdict(lambda: defaultdict(list))
    
    for url_obj in urls:
        for param in url_obj['parameters']:
            key = param['key']
            value = param['value'] if param['value'] else '(empty)'
            param_data[key][value].append(url_obj['url'])
    
    return param_data

def get_co_occurrence(urls, target_param):
    """Calculate parameter co-occurrence"""
    co_occurrence = defaultdict(int)
    
    for url_obj in urls:
        param_keys = [p['key'] for p in url_obj['parameters']]
        if target_param in param_keys:
            for key in param_keys:
                if key != target_param:
                    co_occurrence[key] += 1
    
    return sorted(co_occurrence.items(), key=lambda x: x[1], reverse=True)[:10]

# Initialize session state
if 'urls' not in st.session_state:
    st.session_state.urls = []
if 'param_tags' not in st.session_state:
    st.session_state.param_tags = {}

# Header
st.title("🔍 Burp Suite Parameter Tracker")
st.markdown("Analyze parameters and find vulnerabilities")

# File upload
uploaded_file = st.file_uploader("Upload Burp Suite HTML export", type=['html'])

if uploaded_file is not None:
    html_content = uploaded_file.read().decode('utf-8')
    
    with st.spinner('Parsing HTML...'):
        st.session_state.urls = parse_burp_html(html_content)
    
    file_size = len(html_content) / (1024 * 1024)
    st.success(f"✅ Loaded {len(st.session_state.urls)} URLs ({file_size:.2f} MB)")

# Main interface
if st.session_state.urls:
    param_data = get_parameter_data(st.session_state.urls)
    all_params = sorted(param_data.keys())
    
    # Stats
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("URLs", len(st.session_state.urls))
    with col2:
        st.metric("Parameters", len(all_params))
    with col3:
        total_instances = sum(
            len(urls) 
            for param_values in param_data.values() 
            for urls in param_values.values()
        )
        st.metric("Total Instances", total_instances)
    
    st.divider()
    
    # Sidebar for parameter list
    with st.sidebar:
        st.header("Parameters")
        search_term = st.text_input("🔎 Search", placeholder="Filter parameters...")
        
        # Filter parameters
        filtered_params = [p for p in all_params if search_term.lower() in p.lower()]
        
        st.caption(f"Showing {len(filtered_params)} of {len(all_params)} parameters")
        
        # Parameter selection
        selected_param = st.radio(
            "Select parameter:",
            filtered_params,
            label_visibility="collapsed",
            format_func=lambda x: f"{x} ({sum(len(urls) for urls in param_data[x].values())}×)"
        )
    
    # Main content area
    if selected_param:
        st.header(f"📊 {selected_param}")
        
        # Parameter info
        values = param_data[selected_param]
        total_occurrences = sum(len(urls) for urls in values.values())
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Occurrences", total_occurrences)
        with col2:
            st.metric("Unique Values", len(values))
        
        # Auto tags
        auto_tags = get_auto_tags(selected_param)
        if auto_tags:
            st.markdown("**🤖 Auto Tags:**")
            cols = st.columns(len(auto_tags))
            for idx, tag in enumerate(auto_tags):
                with cols[idx]:
                    st.markdown(f"<span style='background-color: #FED7AA; padding: 4px 12px; border-radius: 12px; font-size: 14px;'>{tag}</span>", unsafe_allow_html=True)
        
        # Manual tags
        st.markdown("**🏷️ Manual Tags:**")
        if selected_param not in st.session_state.param_tags:
            st.session_state.param_tags[selected_param] = []
        
        col1, col2 = st.columns([3, 1])
        with col1:
            new_tag = st.text_input("Add tag", key=f"tag_input_{selected_param}", placeholder="e.g., Tested, Critical, Skip")
        with col2:
            if st.button("Add", key=f"add_tag_{selected_param}"):
                if new_tag and new_tag not in st.session_state.param_tags[selected_param]:
                    st.session_state.param_tags[selected_param].append(new_tag)
                    st.rerun()
        
        # Display manual tags
        if st.session_state.param_tags[selected_param]:
            tag_cols = st.columns(len(st.session_state.param_tags[selected_param]))
            for idx, tag in enumerate(st.session_state.param_tags[selected_param]):
                with tag_cols[idx]:
                    if st.button(f"❌ {tag}", key=f"remove_{selected_param}_{tag}"):
                        st.session_state.param_tags[selected_param].remove(tag)
                        st.rerun()
        
        st.divider()
        
        # Relationships
        with st.expander("🔗 View Parameter Relationships"):
            co_occurrence = get_co_occurrence(st.session_state.urls, selected_param)
            
            if co_occurrence:
                st.markdown(f"Parameters that appear together with **{selected_param}**:")
                
                for param, count in co_occurrence:
                    col1, col2, col3 = st.columns([3, 1, 1])
                    with col1:
                        param_tags = get_auto_tags(param)
                        tag_str = " ".join([f"`{t}`" for t in param_tags[:2]])
                        st.markdown(f"**{param}** {tag_str}")
                    with col2:
                        st.caption(f"{count} times")
                    with col3:
                        if st.button("View", key=f"view_{param}"):
                            st.session_state.selected_param = param
                            st.rerun()
                
                st.info("💡 **Pentesting Tip:** Parameters that frequently appear together might share validation logic. If you find a vulnerability in one, test the related ones!")
            else:
                st.warning("This parameter doesn't appear with any other parameters")
        
        st.divider()
        
        # Values and URLs
        st.subheader("Values & URLs")
        
        for value, url_list in values.items():
            with st.expander(f"**Value:** `{value}` ({len(url_list)} URLs)", expanded=len(values) == 1):
                for url in url_list:
                    st.markdown(f"- [{url}]({url})")
        
        # Export functionality
        st.divider()
        if st.button("📥 Export Parameter Data to CSV"):
            # Prepare data for export
            export_data = []
            for value, url_list in values.items():
                for url in url_list:
                    export_data.append({
                        'Parameter': selected_param,
                        'Value': value,
                        'URL': url,
                        'Auto Tags': ', '.join(auto_tags),
                        'Manual Tags': ', '.join(st.session_state.param_tags.get(selected_param, []))
                    })
            
            df = pd.DataFrame(export_data)
            csv = df.to_csv(index=False)
            
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name=f"{selected_param}_analysis.csv",
                mime="text/csv"
            )

else:
    st.info("👆 Upload a Burp Suite HTML export to get started")
    
    st.markdown("---")
    st.markdown("### How to use:")
    st.markdown("""
    1. In Burp Suite, go to **Target** → **Site map**
    2. Right-click on your target → **Engagement tools** → **Analyze target**
    3. Save the HTML report
    4. Upload it here
    
    This tool will help you:
    - 🔍 Track all parameters across endpoints
    - 🤖 Auto-tag potential vulnerabilities
    - 🔗 Find parameter relationships
    - 🏷️ Add custom tags for your testing workflow
    """)
