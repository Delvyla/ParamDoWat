from bs4 import BeautifulSoup
import sys

def extract_dynamic_urls(input_file, output_file):
    """
    Extract only the Dynamic URLs section from Burp Suite HTML export
    and save it to a new file
    """
    print(f"Reading file: {input_file}")
    
    # Read the file
    with open(input_file, 'rb') as f:
        html_content = f.read().decode('utf-8', errors='replace')
    
    print(f"File size: {len(html_content)} characters")
    
    # Parse with BeautifulSoup
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Find all h2 tags
    print("\nFound H2 tags:")
    for h2 in soup.find_all('h2'):
        print(f"  - {h2.get_text(strip=True)}")
    
    # Find the Dynamic URLs h2
    target_h2 = None
    for h2 in soup.find_all('h2'):
        h2_text = h2.get_text(strip=True)
        if 'Dynamic' in h2_text and 'URL' in h2_text:
            target_h2 = h2
            print(f"\nFound target H2: {h2_text}")
            break
    
    if not target_h2:
        print("ERROR: Could not find 'Dynamic URLs' header")
        sys.exit(1)
    
    # Find the UL after this h2
    ul = target_h2.find_next_sibling('ul')
    
    if not ul:
        print("ERROR: No UL found after Dynamic URLs header")
        sys.exit(1)
    
    print(f"Found UL with {len(list(ul.children))} children")
    
    # Count URLs
    url_count = 0
    for li in ul.find_all('li', recursive=False):
        text = li.get_text(strip=True)
        if text.startswith('http'):
            url_count += 1
    
    print(f"Found {url_count} URLs")
    
    # Create new HTML with just the Dynamic URLs section
    new_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Dynamic URLs - Extracted</title>
    <meta charset="UTF-8">
</head>
<body>
<h2>Dynamic URLs</h2>
{str(ul)}
</body>
</html>"""
    
    # Write to output file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(new_html)
    
    print(f"\nExtracted section saved to: {output_file}")
    print(f"Output file size: {len(new_html)} characters")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python extract_dynamic_urls.py <input.html> <output.html>")
        print("\nExample:")
        print("  python extract_dynamic_urls.py burp_export.html dynamic_only.html")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    extract_dynamic_urls(input_file, output_file)
