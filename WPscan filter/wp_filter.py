import re
import os

def read_file(filename):
    with open(filename, 'r') as file:
        return file.read()

current_directory = os.path.dirname(os.path.abspath(__file__))
filePath = os.path.join(current_directory, 'wpscan.txt')
wp_output = read_file(filePath)


