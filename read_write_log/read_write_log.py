# read_write_log.py

def filter_log(input_file, output_file, keywords):
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            for keyword in keywords:
                if keyword in line:
                    outfile.write(line)


input_log_file = '/Users/matteoercolino/Desktop/input.log'
output_log_file = '/Users/matteoercolino/Desktop/output.log'
keywords_of_interest = ['ERROR', 'WARNING', 'CRITICAL']

filter_log(input_log_file, output_log_file, keywords_of_interest)