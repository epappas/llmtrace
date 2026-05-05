import os

def on_post_page(output, page, config):
    """
    Hook to save a clean version of the Markdown source (without YAML front matter)
    to the site directory alongside the HTML version.
    """
    # page.markdown at this stage is the raw markdown after front matter extraction
    # and after any markdown extensions have been applied (if we used on_page_markdown).
    # However, 'page.markdown' is populated before 'on_post_page'.
    
    # Determine the destination path for the .md file
    # If use_directory_urls is true, abs_dest_path is .../index.html
    # We change it to .../index.md
    dest_path = os.path.splitext(page.file.abs_dest_path)[0] + ".md"
    
    # Ensure the destination directory exists (though it should already exist for the .html file)
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    
    # Write the clean markdown (MkDocs already stripped the YAML header)
    with open(dest_path, 'w', encoding='utf-8') as f:
        f.write(page.markdown)
