import csv

input_file = 'malicious_phish1.csv'
output_file = 'defacement_urls.csv'

with open(input_file, 'r', newline='', encoding='utf-8') as infile, \
     open(output_file, 'w', newline='', encoding='utf-8') as outfile:
    
    reader = csv.DictReader(infile)
    writer = csv.DictWriter(outfile, fieldnames=['url'])
    
    writer.writeheader()  # 寫入標題列
    
    for row in reader:
        if row['type'].strip().lower() == 'defacement':
            writer.writerow({'url': row['url']})

