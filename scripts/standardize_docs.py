import os
import re
import yaml

DOCS_DIR = "/Users/geo/Projects/llmtrace/docs"
MKDOCS_YML = "/Users/geo/Projects/llmtrace/mkdocs.yml"

def get_referenced_files():
    files = []
    with open(MKDOCS_YML, 'r') as f:
        content = f.read()
    
    # Extract .md files using simple regex
    matches = re.findall(r'[:\s]+([\w\-\./]+\.md)', content)
    for m in matches:
        if m not in files:
            files.append(m)
    return files

def standardize_content(content):
    # 1. UK English Replacements (Case insensitive but keeping original case is hard, so we do targeted replacements)
    replacements = [
        (r'\b(A|a)uthoriz(e|es|ed|ing|ation)\b', r'\1uthoris\2'),
        (r'\b(O|o)ptimiz(e|es|ed|ing|ation)\b', r'\1ptimis\2'),
        (r'\b(C|c)ustomiz(e|es|ed|ing|ation)\b', r'\1ustomis\2'),
        (r'\b(O|o)rganiz(e|es|ed|ing|ation)\b', r'\1rganis\2'),
        (r'\b(S|s)tandardiz(e|es|ed|ing|ation)\b', r'\1tandardis\2'),
        (r'\b(A|a)nalyz(e|es|ed|ing)\b', r'\1nalys\2'),
        (r'\b(B|b)ehavior(s)?\b', r'\1ehaviour\2'),
        (r'\b(C|c)olor(s)?\b', r'\1olour\2'),
        (r'\b(D|d)atacenter(s)?\b', r'\1ata centre\2'),
        (r'\b(C|c)enter(s)?\b', r'\1entre\2'), # Can be risky, but usually okay in docs. Might skip this general one to avoid breaking code like text-align: center
    ]
    
    # Let's skip raw code blocks before applying text replacements to avoid breaking code
    # We will split by code block fences
    parts = re.split(r'(```.*?```)', content, flags=re.DOTALL)
    
    for i in range(0, len(parts), 2): # only modify text, not code blocks
        text = parts[i]
        
        # Apply UK English
        for pattern, replacement in replacements:
            if pattern == r'\b(C|c)enter(s)?\b':
                # Only replace center if not in CSS/HTML like "text-align: center" or "<center>"
                text = re.sub(r'(?<!text-align: )\b(C|c)enter(s)?\b', r'\1entre\2', text)
            else:
                text = re.sub(pattern, replacement, text)
        
        # 3. Markdown Formatting
        
        # Headings: De-punctuation (remove trailing colon)
        text = re.sub(r'^(#+\s+.*):\s*$', r'\1', text, flags=re.MULTILINE)
        
        # Headings: De-numbering (remove "1. ", "2.3. ", etc.)
        text = re.sub(r'^(#+)\s+(?:\d+\.)+\s*(.*)$', r'\1 \2', text, flags=re.MULTILINE)
        
        # Lists & Points: De-numbering (replace numbered lists with bullets)
        # Note: only replace if it's the start of a line
        text = re.sub(r'^(\s*)\d+\.\s+', r'\1- ', text, flags=re.MULTILINE)
        
        # Lists & Points: Prohibited Bold Points -> Bold Paragraphs
        # e.g. "- **Key**: Description" -> "\n**Key**: Description\n"
        text = re.sub(r'^(\s*)[\-\*]\s+\*\*(.*?)\*\*(?:\s*:\s*|\s+\-\s+|\s+)(.*)$', r'\n**\2**: \3\n', text, flags=re.MULTILINE)
        
        # Callouts: Blockquotes to Admonitions
        # We will only convert Github standard alerts for now, e.g. > [!NOTE] -> !!! note
        text = re.sub(r'^>\s*\[!(NOTE|IMPORTANT|WARNING|CAUTION|TIP)\]\n((?:^>.*\n)*)', 
                      lambda m: f"!!! {m.group(1).lower()}\n" + m.group(2).replace("> ", "    ").replace(">", "    "), 
                      text, flags=re.MULTILINE)
        
        # Remove AI Signature sections if they are empty or generic "Conclusion" / "Summary"
        text = re.sub(r'^(#+)\s+(Conclusion|Summary)\s*\n(?!.*(?:Next Steps|Key Takeaways))', r'\1 \2\n', text, flags=re.IGNORECASE | re.MULTILINE)
        
        parts[i] = text
        
    content = "".join(parts)
    
    # De-titling code blocks
    content = re.sub(r'```(\w+)\s+(title|filename)=["\'].*?["\']', r'```\1', content)
    
    # Remove Horizontal Rules (--- or ***) that are outside YAML frontmatter
    # YAML frontmatter is at the very start
    lines = content.split('\n')
    in_frontmatter = False
    new_lines = []
    for idx, line in enumerate(lines):
        if idx == 0 and line.strip() == '---':
            in_frontmatter = True
            new_lines.append(line)
            continue
        if in_frontmatter and line.strip() == '---':
            in_frontmatter = False
            new_lines.append(line)
            continue
            
        if not in_frontmatter and re.match(r'^(\-\-\-|\*\*\*)$', line.strip()):
            continue # skip horizontal rules
            
        new_lines.append(line)
        
    return '\n'.join(new_lines)


def main():
    files = get_referenced_files()
    print(f"Found {len(files)} files referenced in mkdocs.yml")
    
    changed_count = 0
    for file_path in files:
        full_path = os.path.join(DOCS_DIR, file_path)
        if not os.path.exists(full_path):
            # check if it's at root instead of docs/
            full_path = os.path.join("/Users/geo/Projects/llmtrace", file_path)
            if not os.path.exists(full_path):
                print(f"Missing file: {file_path}")
                continue
                
        with open(full_path, 'r', encoding='utf-8') as f:
            original_content = f.read()
            
        new_content = standardize_content(original_content)
        
        if new_content != original_content:
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            changed_count += 1
            print(f"Updated: {file_path}")
            
    print(f"Total files updated: {changed_count}")

if __name__ == "__main__":
    main()
