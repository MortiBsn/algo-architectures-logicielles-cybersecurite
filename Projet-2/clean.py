import os
import subprocess

def delete_files_with_extensions(directory, extensions):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(extensions):
                file_path = os.path.join(root, file)
                os.remove(file_path)
                print(f"Deleted: {file_path}")

if __name__ == "__main__":
    directory = os.path.dirname(os.path.abspath(__file__))
    extensions = ('.p12', '.pem', '.crt', '.json')
    delete_files_with_extensions(directory, extensions)