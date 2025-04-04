import pdfkit
import os

def convert_html_to_pdf(input_html, output_pdf):
    # Ensure the file exists
    if not os.path.exists(input_html):
        print(f"File not found: {input_html}")
        return

    # Convert HTML to PDF
    pdfkit.from_file(input_html, output_pdf)
    print(f"PDF saved successfully at {output_pdf}")

if __name__ == "__main__":
    input_html = './Picture1.html'  # Path to your HTML file
    output_pdf = 'output_file.pdf'  # Path where the PDF should be saved

    convert_html_to_pdf(input_html, output_pdf)
