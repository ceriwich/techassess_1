# Analyzing VPC Flow Log Data

Developer: Cerina Wichryk

## About

This VPC Flow Log Analysis tool is a Python program that takes two required command line arguments and includes a pair of optional command line arguments.

- `flow_log_fn`: Required argument. File name for the flow log data. Must be a plain text (.txt) file with either pre-existing flow log data or contents that will be overwritten by randomly generated data.
- `lookup_table_fn`: Required argument. File name for the port/protocol to tag mappings known as the lookup table, must be a plain text (.txt) file with either pre-existing flow log data or contents that will be overwritten by randomly generated data.
- `-fle/--flow_log_entries`: Optional argument, but must be used with `--lookup_entries`. Integer that determines how many flow log entries to generate
- `-le/--lookup_entries`: Optional argument, but must be used with `--flow_log_entries`. Integer that determines how many lookup table entries to generate

Processing randomly generated data is mainly used for testing purposes. Since creating flow logs from a VPC is costly and there are essentially zero public files for sample data, this is a way to test the system for free.

The main script has functions for both parsing the file and randomly generating files to test from. Upon a successful command, the program will generate an output file called `output.txt` containing both the frequencies of tags and the frequencies of port/protocol combinations.

Information on flow logs was based on the [Amazon Virtual Private Cloud User Guide](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html)

Protocol number to keyword mappings followed the [Assigned Internet Protocol Numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)

All libraries used in `log_parser.py` are native to the Python language

### Assumptions

The program only supports the default VPC flow log format. The only supported log version is version 2. The program can handle at maximum 10,000 lookup entries and 10MB of flow log entries at once. 


## How to Run

Make sure you have [Python](https://www.python.org/downloads/) downloaded on your machine. After downloading the files from above, you can run the program via command line/terminal. First, navigate to the correct folder.

```
cd techassess_1
```
Then, execute one of two variations. The first for pre-existing data. When using this version, both files must already exist in the directory.
```
python log_parser.py logs.txt lookup.txt
```
Or the alternative for randomly generated data. When using this variation, both files may or may not exist. If they do exist, their data will be overwritten.
```
python log_parser.py logs.txt lookup.txt -fle 5000 -le 1500
```


## Other Analysis

The randomly generated feature was used to test how the program processed each file line by line throughout development. It also served to gauge the elapsed time of the program. 

The sample data given takes approximately 0.006 seconds to process, while the maximum capacity of the system (10MB of flow logs, 10,000 lookup table entries) takes approximately 6 minutes to process

## Closing and Further Remarks
If I were to continue this project further, I would attempt to optimize the time it takes to parse these text files. It would take some personal research and learning to devise a better strategy. 

I would also add that the files would be completely overwritten from a possibly pre-existing file when using randomly generated data.

I would also like to expand the testing capabilities to handle more obscure details about flow logs. For example, when a field in the flow log is inapplicable or couldn't be computed, then the field only contains the '-' character. The log status for this kind of flow log record would be either `NODATA` or `SKIPDATA`. Given more time, integrating this case would be most useful. 

Another detail that was not included due to time was that the fields must be in order to fulfill default and version 2 constraints. Including a mechanism to check each field's validity (such as IP addresses and port numbers) would be a way to ensure the validity of the flow log data. 


