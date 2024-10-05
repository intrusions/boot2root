import os
import re

directory = "./ft_fun/"
fragments = {}
pattern = re.compile(r'//file(\d+)')

for filename in os.listdir(directory):
    filepath = os.path.join(directory, filename)
    
    with open(filepath, 'r') as file:
        content = file.read()
        match = pattern.search(content)
        file_number = int(match.group(1))
        fragments[file_number] = content.strip()

    ordered_fragments = dict(sorted(fragments.items()))

    with open("main.c", "w") as output_file:
        for _, fragment in ordered_fragments.items():
            output_file.write(fragment + "\n")
