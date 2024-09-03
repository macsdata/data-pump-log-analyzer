# Data Pump Log Analyzer

A command-line tool written in Python for analyzing Oracle Data Pump log files. This script enables users to efficiently extract, filter, and display detailed information from Data Pump logs, providing comprehensive insights into key metrics and performance data.  
For more detailed information and examples have a look at the [Comprehensive Guide](https://macsdata.com/oracle/data-pump-log-analyzer-guide).

## Features

- Detailed operations and data processing information
- Errors / ORA- Messages analysis
- Examine object type information
- Analyze Data Pump workers performance
- Summarised view by schema, table, partition, subpartition
- View data processed by instance (21c and later)
- Filter, sort and limit output 
- Export report to text or html format

## Important Information

This script primarily relies on the log data provided by Oracle Data Pump. It is crucial to understand that this script is only as accurate as the data it processes. Also before making any decisions based on the script's output, you should always verify the results by checking the original Data Pump log files which contain the authoritative information. The Data Pump Log Analyzer is intended to assist with analysis, not replace the need for thorough review.

## Usage

```bash
python3 dpla.py <logfile> [options]
```

### Options

```
-h, --help            show this help message and exit
-v, --version         show program's version number and exit
-e [MESSAGE ...], --error [MESSAGE ...]
                      show error details (optionally specify error(s) as a filter
-o, --object          show object type details
-w, --worker          show worker details
-s [SCHEMA ...], --schema [SCHEMA ...]
                      show schema details (optionally specify schema(s) as a filter
-t [TABLE ...], --table [TABLE ...]
                      show table details (optionally specify table(s) as a filter
-i, --instance        show instance details (starting 21c)
-a, --all             show complete output
--sort <column>       specify column name to sort the tables by
--top <N|all>         specify number of top rows to display (use 'all' for no limit)
--output <filename>   specify output file. For HTML output, use .htm or .html extension
```

### Examples

- **Show error / ORA- messages info:**
  ```bash
  python3 dpla.py file.log -e
  ```

- **Save complete output to an HTML file:**
  ```bash
  python3 dpla.py file.log -a --output dpla-report.html
  ```

- **Show schema info for specific schemas:**
  ```bash
  python3 dpla.py file.log -s HR SCOTT
  ```

- **Display top 10 tables sorted by size:**
  ```bash
  python3 dpla.py file.log -t --sort size --top 10
  ```

## About This Project

Please note that I'm not a professional developer. I created this project in an effort to help others who might face similar challenges. While I have tested the script and tried to ensure it works correctly, there may be limitations or issues I haven't encountered. Feedback and suggestions are always welcome!

## Contributing

Contributions are welcome! Please open an issue or contact me if you have ideas for improvements or new features.

## License

This project is licensed under the Universal Permissive License (UPL), Version 1.0.  
See the [LICENSE](LICENSE) file for more details.

## Disclaimer

This is a personal project and repository. The views and code presented here are my own and do not reflect those of my employer or any other organization. Use this project at your own discretion and responsibility.

