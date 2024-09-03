#!/usr/bin/env python3
"""
Script Name:    dpla.py
Description:    Data Pump Log Analyzer
                Parse and analyze Oracle Data Pump log files
                Requires Python 3.6
                Copyright (c) 2024 Marcus Doeringer / macsdata
                Licensed under the Universal Permissive License v 1.0
Usage:          Run this script from the command line 
                python3 dpla.py or ./dpla.py
                Use -h or --help to show all options
Author:         Marcus Doeringer
"""

__version__ = "0.9.2"

import re
import argparse
import os
import sys
from collections import defaultdict
from datetime import datetime

# Defaults
defaults = {
    'oramsg': {'sort': 'count', 'top': None},
    'object': {'sort': 'seconds', 'top': None},
    'worker': {'sort': 'seconds', 'top': None},
    'schema': {'sort': 'seconds', 'top': None},
    'table': {'sort': 'seconds', 'top': 30},
    'instance': {'sort': 'seconds', 'top': None}
}
indent = " "

# Define aggregation methods
aggr_methods = {
    'count': sum,
    'instance': max,
    'workers': max
}
aggr_default = sum

# Initialize dictionaries
oramsg_stats = defaultdict(lambda: {'count': 0})
worker_stats = defaultdict(lambda: {'instance': 0, 'objects': 0, 'size': 0.0, 'seconds': 0})
schema_stats = defaultdict(lambda: {'objects': 0, 'size': 0.0, 'seconds': 0})
table_stats = defaultdict(lambda: {'rows': 0, 'size': 0.0, 'seconds': 0, 'part': set(), 'subpart': 0})
object_stats = defaultdict(lambda: {'count': 0, 'seconds': 0, 'workers': set(), 'duration': 0})
instance_stats = defaultdict(lambda: {'workers': set(), 'objects': 0, 'size': 0.0, 'seconds': 0})

# Global regex patterns
operation_re = re.compile(r'(?P<operation>Import|Export): .+ on (?P<starttime>.+)$')
starttime_re = re.compile(r'(?P<starttime>^.+?)\.?\d{3}?:')
jobname_re = re.compile(r'Starting .+"\."(?P<jobname>[\w_]+)":')
dpversion_re = re.compile(r'^Version\s+(?P<dpversion>.+)$')
dbinfo_re = re.compile(r'Connected to: (?P<dbinfo>.+) -.+$')
endtime_re = re.compile(r'Job.+ completed(?: with (?P<errors>\d+) error\(s\))? at (?P<endtime>[\w\s:]+) elapsed .+$')
worker_re = re.compile(r'W-(?P<worker>\d+).*?Startup(?: on instance (?P<instance>\d+))? took')
oramsg_re = re.compile(r'(?P<errid>ORA-\d{5}): (?P<errmsg>.+)$')
oramsg_delpattern = [
    re.compile(r'[:\.]?["\'][^"\']*["\']')   # Matches anyhting within single or double quotes with : and .
]
data_re = re.compile(
    r'W-(?P<worker>\d+)?\s*\.\s*\.\s*'
    r'(?P<operation>imported|exported)\s+"'
    r'(?P<schema>[^"]+)"\."(?P<table>[^"]+)"'
    r'(?:\:"(?P<partition>[^"]+)"(?:\."(?P<subpartition>[^"]*)")?)?'
    r'\s+(?P<size>\d+(?:\.\d*)?)\s+'
    r'(?P<unit>KB|MB|GB|TB)\s+'
    r'(?P<rows>\d+) rows'
    r'(?: in (?P<seconds>\d+) seconds?)?'
    r'(.*)$'
)
object_re = re.compile(
    r'Completed(?: by worker (?P<worker>\d+))? '
    r'(?P<ocount>\d+) '
    r'(?P<otype>[A-Z_/]+) '
    r'objects in '
    r'(?P<seconds>\d+) seconds'
)
otype_re = re.compile(r"Processing object type (?P<otype>.+)$")


# Classes
class OutputRedirector:
    # Used to redirect output to file
    def __init__(self, filename=None):
        self.filename = filename
        self.original_stdout = sys.stdout
        self.file = None

    def __enter__(self):
        if self.filename:
            if os.path.exists(self.filename):
                overwrite = input(f"File '{self.filename}' already exists. Overwrite? (y/n): ").strip().lower()
                if overwrite != 'y':
                    pmesg("Operation aborted. Output will not be redirected.", 'info', 1)
            try:
                self.file = open(self.filename, 'w')
                sys.stdout = self.file
            except IOError as e:
                pmesg(f"Unable to write to file '{self.filename}':\n {str(e)}", 'error', 1)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.file:
            self.file.close()
        sys.stdout = self.original_stdout


class Colors:
    BLUE = '\033[94m'     # BLUE
    GREEN = '\033[92m'    # GREEN
    YELLOW = '\033[93m'   # YELLOW
    RED = '\033[91m'      # RED
    RESET = '\033[0m'     # Reset


def pmesg(message, level="info", exitcode=None):
    """
    Prints a message based on the level and handles program exit if needed.

    :param message: message to print
    :param level: severity level ('info', 'warning', 'error').
    :param exit_code: If provided, exits the program with this code.
    """
    prog = os.path.basename(sys.argv[0])
    if level == "error":
        print(f"{prog}: error: {message}", file=sys.stderr)
    elif level == "warning":
        print(f"{prog}: warning: {message}", file=sys.stderr)
    else:
        print(f"{prog}: info: {message}")

    if exitcode is not None:
        sys.exit(exitcode)


def parse_arguments():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Data Pump Log Analyzer")

    # positional arguments
    # parser.add_argument('files', nargs='+', help="specify one or two Data Pump logfiles")
    parser.add_argument('file', nargs=1, type=str, help="specify a Data Pump logfile")

    # Optional mode options
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('-e', '--error', metavar='MESSAGE', nargs='*', help="show error details (optionally specify error(s) as a filter")
    parser.add_argument('-o', '--object', action='store_true', help="show object type details")
    parser.add_argument('-w', '--worker', action='store_true', help="show worker details")
    parser.add_argument('-s', '--schema', metavar='SCHEMA', nargs='*', help="show schema details (optionally specify schema(s) as a filter")
    parser.add_argument('-t', '--table', metavar='TABLE', nargs='*', help="show table details (optionally specify table(s) as a filter")
    parser.add_argument('-i', '--instance', action='store_true', help="show instance details (starting 21c)")
    parser.add_argument('-a', '--all', action='store_true', help="show complete output")

    # Optional additional options
    parser.add_argument('--sort', metavar='<column>', type=str, help="specify column name to sort the tables by")
    parser.add_argument('--top', metavar='<N|all>', type=str, help="specify number of top rows to display (use 'all' for no limit)")
    parser.add_argument('--output', metavar='<filename>', type=str, help="specify output file. For HTML output, use .htm or .html extension")

    args = parser.parse_args()
    toprows = None

    if args.top == 'all':
        # Interpret 'all' as no limit
        toprows = None
    elif args.top is not None:
        # Convert to integer if top argument was specified
        try:
            toprows = int(args.top)
        except ValueError:
            parser.error("--top argument must be a number or 'all'.")

    return args, toprows


def get_extension(filename):
    """
    Gets and returns the file extension for a given file

    :param filename: file
    """
    _, ext = os.path.splitext(filename.lower())
    return 'html' if ext in ('.htm', '.html') else 'text'


def format_size(size_mb):
    """
    Converts and formats a size in megabytes (MB) to the appropriate unit (KB, MB, GB, TB).

    :param size_mb: Size in MB
    """
    if size_mb < 1:
        return f"{size_mb * 1024:.2f} KB"
    elif size_mb < 1024:
        return f"{size_mb:.2f} MB"
    elif size_mb < 1024 * 1024:
        return f"{size_mb / 1024:.2f} GB"
    else:
        return f"{size_mb / 1024 / 1024:.2f} TB"


def format_time(seconds):
    """
    Converts seconds into readable time format with hours, minutes and seconds
    Currently no in use

    :param seconds: Seconds
    """
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}h {minutes}m {seconds}s" if hours else f"{minutes}m {seconds}s" if minutes else f"{seconds}s"


def is_defaultdict_empty(d):
    """Check if a defaultdict is effectively empty (contains only default values)."""
    if not isinstance(d, defaultdict):
        return not bool(d)
    return all(
        (isinstance(v, dict) and not v) or
        (isinstance(v, set) and not v) or
        (isinstance(v, (int, float)) and v == 0)
        for v in d.values()
    )


def file_valid(report):
    """
    Checks if some variable that are reported are found in the specified logfile

    :param report: Displayed report information
    """
    # List of variables to check in the report
    vars_check = ['operation', 'starttime', 'jobname']

    # Check specific variables in the report
    vars_unset = [var for var in vars_check if not report.get(var)]

    is_valid = len(vars_unset) == 0

    return {
        'valid': is_valid,
        'vars_unset': vars_unset
    }


def file_metrics(dict_list):
    """
    Checks if additional information is found in logfile when METRICS is specified

    :param dict_list: List of dictionaries
    """
    # Check if specific dictionaries are effectively empty
    empty_dicts = [dict_name for dict_name in dict_list
                   if is_defaultdict_empty(globals().get(dict_name, {}))]

    is_valid = len(empty_dicts) == 0

    return {
        'valid': is_valid,
        'empty_dicts': empty_dicts
    }


def clean_error_messages(error, patterns):
    """
    Remove schema and object names from ORA messages

    :param error: error message
    :param patterns: regex pattern how to remove the info
    """
    cleaned_error = error
    for pattern in patterns:
        cleaned_error = re.sub(pattern, '', cleaned_error)
    # Remove extra spaces
    cleaned_error = re.sub(r'\s+', ' ', cleaned_error).strip()
    return cleaned_error


def validate_files(files):
    """
    Check if the files are valid and readable, and return their filenames along with modification timestamps
    """
    files_valid = []

    for file in files:
        if os.path.isfile(file) and os.access(file, os.R_OK):
            timestamp = datetime.fromtimestamp(os.path.getmtime(file)).strftime("%a %b %d %H:%M:%S %Y")
            files_valid.append((file, timestamp))
        else:
            pmesg(f"file '{file}' is not valid or not readable", 'error', 1)

    return files_valid


def safe_get(record, key, default=0):
    """Safely get a value from a dictionary with a default if the key is not found."""
    return record.get(key, default) if isinstance(record, dict) else default


def print_report_header(title):
    """Prints report header"""
    print(f"\n{'=' * (len(title)+2)}\n {title}\n{'=' * (len(title)+2)}\n")


def print_section_header(title):
    """Prints section header"""
    print(f"\n{title}\n{'~' * len(title)}")


def print_aligned(label, value, width=20, color=Colors.RESET):
    """Formatted print output with fixed width"""
    if sys.stdout.isatty():
        print(f"{indent}{label:<{width}}{color}{value}{Colors.RESET}")
    else:
        print(f"{indent}{label:<{width}}{value}")


def print_report(report, files_info):
    """
    Print the text report

    :param report: report dict
    :param files_info: files information
    """

    max_label_length = 28

    print_report_header("Data Pump Log Analyzer")

    # print_section_header("DPLA Details")
    print_aligned("Version:", report['version'], max_label_length)
    print_aligned("Arguments:", report['argslist'], max_label_length)
    print_aligned("Generated:", report['generated'], max_label_length)

    print_section_header("Logfile Details")
    for file, timestamp, metrics, mtext, mcolor, mclass in files_info:
        print_aligned("Analyzed File:", os.path.basename(file), max_label_length)
        print_aligned("File Timestamp:", timestamp, max_label_length)
        print_aligned("Metrics:", mtext, max_label_length, mcolor)

        print_section_header("Operation Details")
        print_aligned("Operation:", report['operation'] or "Not found", max_label_length)
        print_aligned("Data Pump Version:", report['dpversion'] or "Not found", max_label_length)
        print_aligned("DB Info:", report['dbinfo'] or "Not found", max_label_length)
        print_aligned("Job Name:", report['jobname'] or "Not found", max_label_length)
        print_aligned("Status:", report['opstatus'] or "Not found", max_label_length, report['opcolor'])
        print_aligned("  Processing:", report['processing'], max_label_length)
        print_aligned("Errors:", report['errors'], max_label_length, report['errcolor'])
        print_aligned("  ORA- Messages:", report['oramsgs'], max_label_length, report['oracolor'])
        print_aligned("Start Time:", report['starttime'] or "Not found", max_label_length)
        print_aligned("End Time:", report['endtime'] or "Not found", max_label_length)
        print_aligned("Runtime:", report['runtime'] or "Not found", max_label_length)

        max_label_length = 28
        print_section_header("Data Processing")
        print_aligned("Parallel Workers:", report['workers'] or "Not found", max_label_length)
        print_aligned("Schemas:", report['schemas'] or "Not found", max_label_length)
        print_aligned("Objects:", report['objects'] or "Not found", max_label_length)
        print_aligned("Data Objects:", report['dobjects'] or "Not found", max_label_length)
        print_aligned("Overall Size:", report['totalsize'] or "Not found", max_label_length)


def print_table(headers, rows, alignments, summary=None):
    """
    Print a table with dynamic column widths, headers, rows, and alignments.

    :param headers: List of header titles
    :param rows: List of row data (each row is a list of values)
    :param alignments: List of alignments for each column ('<' for left, '>' for right)
    :param summary: List of summary
    """
    # Calculate column widths
    col_widths = [
        max(len(str(item)) for item in [header] + [row[idx] for row in rows]) + 4
        for idx, header in enumerate(headers)
    ]

    # Header and separator
    header_row = " ".join(f"{headers[idx]:{alignments[idx]}{col_widths[idx]}}" for idx in range(len(headers)))

    separator_segments = [
        "-" * (width) + " " for width in col_widths[:-1]
    ]  # Create segments for all but the last column
    separator_segments.append("-" * col_widths[-1])  # Handle the last column without the trailing space
    separator = "".join(separator_segments)  # Join all segments together

    # Print the header and separator
    ptable = f"{indent}{header_row}\n"
    ptable += f"{indent}{separator}\n"

    # Print rows
    for row in rows:
        ptable += f"{indent}{' '.join(f'{str(row[idx]):{alignments[idx]}{col_widths[idx]}}' for idx in range(len(row)))}\n"

    # Print final separator before summary if summary is provided
    if summary:
        ptable += f"{indent}{separator}\n"  # Separator before summary
        ptable += f"{indent}{' '.join(f'{str(summary[idx]):{alignments[idx]}{col_widths[idx]}}' for idx in range(len(summary)))}\n"

    # Print final separator
    ptable += f"{indent}{separator}"

    return ptable


def section_description(sort, top, filter):
    """Formats the output if filter, sort or top are set"""
    desc = [f"sorted by {sort}"]

    if top is not None:
        desc.append(f"top {top}")

    if isinstance(filter, list) and len(filter) > 0:
        formatted_filters = ', '.join(filter)
        desc.append(f"filtered by {formatted_filters}")

    # Join all parts with commas and close with a parenthesis
    return f"({', '.join(desc)}):\n"


def find_matching_column(sort_key, sample_dict, header):
    """Find matching column for sort operation"""
    lowercase_sort_key = sort_key.lower()
    # Check if the sort key matches the header (dictionary key)
    if lowercase_sort_key == header.lower() or header.lower().startswith(lowercase_sort_key):
        return header

    # Check other dictionary values
    for key in sample_dict.keys():
        if key.lower().startswith(lowercase_sort_key):
            return key
    return None


def safe_sort(items, sort_key, header, section, reverse=True):
    """Sort items based on argument or default value"""
    if not items:
        return [], None

    sample_dict = next(iter(items.values()))
    matching_column = find_matching_column(sort_key, sample_dict, header)

    if matching_column is None:
        # If no matching column is found, use the default value for that section
        matching_column = defaults[section]['sort']

    if matching_column == header:
        # Sort by the dictionary key (first column)
        sorted_items = sorted(
            items.items(),
            key=lambda x: x[0],
            reverse=False
        )
    else:
        # Sort by the matching column in the dictionary values
        sorted_items = sorted(
            items.items(),
            key=lambda x: safe_get(x[1], matching_column),
            reverse=reverse
        )
    return sorted_items, matching_column


def print_section(args, toprows, section, sectitle, colname, stats, filter=None):
    """
    Print a section of output based on the stats data structure.

    :param args: script arguments
    :param toprows: top rows to display
    :param section: the name of the section (e.g., 'worker', 'object').
    :param colname: the name of the first column in the table
    :param stats: stats data for the section
    :param filter: argument specified filter
    """

    sort = args.sort if args.sort else defaults[section]['sort']
    top = toprows if args.top else defaults[section]['top']

    # Applying filter
    if isinstance(filter, list) and len(filter) > 0:
        filtered_stats = {k: v for k, v in stats.items() if any(f.upper() in k.upper() for f in filter)}
    else:
        filtered_stats = stats

    # Sort rows
    sorted_rows, actual_sort = safe_sort(filtered_stats, sort, colname, section)

    # Apply top
    final_rows = sorted_rows[:top]

    print_section_header(f"{sectitle.upper()}")
    print(section_description(actual_sort, top, filter))

    # Assume all items have the same keys, use the first item to determine fields
    if final_rows:
        fields = list(final_rows[0][1].keys())  # Dynamically get fields from the stats dictionary
        headers = [colname.title()] + [field.capitalize() for field in fields]
        alignments = ['<'] + ['>' for _ in fields]

        # Calculate totals

        # Initialize totals with appropriate starting values
        totals = {field: 0 if aggr_methods.get(field, aggr_default) == sum else float('-inf') for field in fields}

        for _, stat in final_rows:
            for field in totals:
                value = stat.get(field, 0)  # Get the value safely
                if isinstance(value, (int, float)):  # Check if the value is numeric
                    agg_func = aggr_methods.get(field, aggr_default)  # Get the appropriate aggregation function
                    if agg_func == sum:
                        totals[field] += value
                    elif agg_func == max:
                        totals[field] = max(totals[field], value)
                elif value == 'N/A':
                    totals[field] = ''

        # Prepare rows for table
        rows = [
            [row[0]] + [format_size(row[1][field]) if field == 'size' else row[1][field] for field in fields]
            for row in final_rows
        ]

        # Prepare summary
        summary = ["Total"] + [
            format_size(totals[field]) if field == 'size' else totals[field] for field in fields
        ]

        print(print_table(headers, rows, alignments, summary))
    else:
        print('No data available.')


def html_head():
    """Head code for the html report"""

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="robots" content="noindex">
        <title>Data Pump Log Analyzer</title>
        {html_css()}
    <noscript>
        <style>
            .collapse-toggle {{ display: none !important; }}
            #scrollToTop {{ display: none !important; }}
            .sticky-header {{ position: static !important; }}
            #toc-toggle {{ display: none !important; }}
            #toc-sidebar {{ display: none !important; }}
            .sort-icons {{ display: none !important; }}
            .search-container {{ display: none !important; }}
        </style>
    </noscript>
    </head>
    """


def html_css():
    """CSS code for the html report"""

    return """
    <style>
        :root {
            --color-primary: #086c91;
            --bg-color: #EDEFF1;
            --text-color: #2c3e50;
            --header-bg-color: var(--color-primary);
            --header-text-color: #fff;
            --header-shadow: 0px 0px 0px var(--color-primary);
            --border-color: #ccd0d5;
            --arrow-color: rgba(255, 255, 255, 0.5);
            --arrow-color-active: #fff;
            --icon-color-light: #3498db;
            --icon-color-dark: #f39c12;
            --input-bg-color: #fff;
            --input-border-color: var(--border-color);
            --input-focus-border-color: var(--color-primary);
            --card-header-text-color: var(--color-primary);
            --card-bg-color: #fff;
            --card-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            --table-bg-color: var(--color-primary);
            --row-odd-color: #f5f6f7;
            --row-even-color: #ffffff;
            --row-hover-color: #dadde1;
            --total-row-bg-color: var(--card-bg-color);
            --total-row-text-color: var(--text-color);
            --toc-bg-color: var(--card-bg-color);
            --totop-color: 8,108,145;

            --status-red-color: #d32f2f;
            --status-yellow-color: #f57f17;
            --status-green-color: #2e7d32;

            --collicon: url("data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24'><path fill='rgba(189, 195, 199, 1)' d='M7.41 15.41L12 10.83l4.59 4.58L18 14l-6-6-6 6z'></path></svg>");
        }
        [data-theme='dark'] {
            --color-primary: #1cbff8;
            --bg-color: #21232A;
            --text-color: #f0f0f0;
            --header-bg-color: #0F1318;
            --header-text-color: #fff;
            --header-shadow: 0px 0px 7px var(--color-primary);
            --border-color: #606770;
            --arrow-color: rgba(236, 240, 241, 0.5);
            --arrow-color-active: #fff;
            --input-bg-color: #2D3039;
            --input-border-color: var(--border-color);
            --input-focus-border-color: var(--color-primary);
            --card-header-text-color: var(--color-primary);
            --card-bg-color: #2D3039;
            --card-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            --table-bg-color: var(--bg-color);
            --row-odd-color: #383C44;
            --row-even-color: #2D3039;
            --row-hover-color: #4A4F5A;
            --total-row-bg-color: var(--card-bg-color);
            --total-row-text-color: var(--header-text-color);
            --toc-bg-color: var(--header-bg-color);
            --totop-color: 28,191,248;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background-color: var(--bg-color);
            color: var(--text-color);
            transition: all 0.3s ease;
        }
        .no-js {
            color: red;
            font-weight: bold;
        }
        .container {
            max-width: 1200px;
            margin: 10px auto;
            padding: 20px;
        }
        .sticky-header {
            position: sticky;
            top: 0;
            background-color: var(--header-bg-color);
            color: var(--header-text-color);
            padding: 12px 20px;
            z-index: 1001;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            display: flex;
            align-items: center;
            box-shadow: var(--header-shadow);
        }
        h1 {
            margin: 0;
        }
        .info-section {
          background-color: var(--card-bg-color);
          border-radius: 10px;
          padding: 20px;
          margin-bottom: 30px;
          margin-top: 20px;
          box-shadow: var(--card-shadow);
        }
        .info-section h2 {
          color: var(--card-header-text-color);
          font-size: 24px;
          margin: 0px;
          border-bottom: 1px solid var(--border-color);
          padding-bottom: 10px;
          cursor: pointer;
          display: flex;
          align-items: center;
        }
        .section-content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
        }
        .section-contenttab {
        }
        .label {
            font-weight: bold;
        }
        .value {
        }
        .highlight {
            display: inline-block;
            width: fit-content;
            padding: 2px 8px;
            margin-left: -8px;
            border-radius: 12px;
            color: var(--header-text-color);
            font-size: 0.95rem;
        }
        .highlight.warn {
            background-color: var(--status-yellow-color);
        }
        .highlight.ok {
            background-color: var(--status-green-color);
        }
        .highlight.fail {
            background-color: var(--status-red-color);
        }
        .collapse-toggle {
            background: var(--collicon) 50% / 1.4rem 1.4rem;
            height: 1.4rem;
            width: 1.4rem;
            transform: rotate(180deg);
            margin-right: 6px;
        }
        .collapse-toggle.collapsed {
            transform: rotate(90deg);
        }
        .section-content,
        .section-contenttab{
            overflow: hidden;
            margin-top: 20px;
        }
        .section-content.collapsed,
        .section-contenttab.collapsed {
            max-height: 0;
            margin-top: 0px;
        }
        .sort-icons {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            display: flex;
            flex-direction: column;
            line-height: 0.5;
        }
        .sort-icons::before,
        .sort-icons::after {
            content: '';
            display: block;
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
        }
        .sort-icons::before {
            border-bottom: 5px solid var(--arrow-color);
            margin-bottom: 3px;
        }
        .sort-icons::after {
            border-top: 5px solid var(--arrow-color);
        }
        th.asc .sort-icons::before {
            border-bottom-color: var(--arrow-color-active);
        }
        th.desc .sort-icons::after {
            border-top-color: var(--arrow-color-active);
        }
        #theme-toggle {
            background: none;
            border: none;
            cursor: pointer;
            font-size: 24px;
            color: var(--header-text-color);
            transition: color 0.3s ease;
        }
        #theme-toggle:hover {
            color: var(--bg-color);
        }
        .search-container {
            margin-bottom: 20px;
        }
        .searchInput {
            width: 100%;
            padding: 12px;
            border: 1px solid var(--input-border-color);
            border-radius: 25px;
            background-color: var(--input-bg-color);
            color: var(--text-color);
            font-size: 16px;
            transition: all 0.3s ease;
            box-sizing: border-box;
        }
        .searchInput:focus {
            border-color: var(--input-focus-border-color);
            outline: none;
        }
        .noResults {
            display: none;
            color: var(--text-color);
            text-align: center;
            padding: 20px;
        }
        table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            border: 1px solid var(--border-color);
            background-color: var(--card-bg-color);
            border-radius: 8px;
            overflow: hidden;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
        }
        table th:not(.text-column),
        table td:not(.text-column) {
            text-align: right;
        }
        table th.text-column,
        table td.text-column {
            text-align: left;
        }
        th {
            background-color: var(--table-bg-color);
            color: var(--header-text-color);
            cursor: pointer;
            position: relative;
            user-select: none;
            white-space: nowrap;
            font-weight: 600;
            padding-right: 30px;
        }
        tbody tr.odd-row {
            background-color: var(--row-odd-color);
        }
        tbody tr.even-row {
            background-color: var(--row-even-color);
        }
        tbody tr:hover {
            background-color: var(--row-hover-color);
        }
        tfoot {
            font-weight: bold;
            background-color: var(--total-row-bg-color);
            color: var(--total-row-text-color);
        }
        tfoot .total-row {
            display: table-row;
        }
        tfoot .filtered-total-row {
            display: none;
        }
        tfoot td {
            border-top: 1px solid var(--border-color);
        }

        #scrollToTop {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background-color: rgba(var(--totop-color),0.7);
            color: white;
            border: none;
            border-radius: 50%;
            width: 48px;
            height: 48px;
            text-align: center;
            cursor: pointer;
            display: none;
            z-index: 1000;
            transition: all 0.3s ease;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2);
        }
        #scrollToTop .arrow {
            display: block;
            width: 8px;
            height: 8px;
            border-top: 2px solid white;
            border-left: 2px solid white;
            transform: rotate(45deg);
            margin: 6px auto 0;
            transition: all 0.3s ease;
        }
        #scrollToTop:hover {
            background-color: rgba(var(--totop-color),0.9);
        }
        #toc-sidebar {
            position: fixed;
            left: -250px;
            margin-top: 40px;
            top: 0px;
            width: 250px;
            height: 100%;
            background-color: var(--toc-bg-color);
            transition: left 0.3s ease;
            z-index: 1000;
            box-shadow: 2px 0 5px rgba(0,0,0,0.1);
        }
        #toc-sidebar.open {
            left: 0;
        }
        .toc-toggle {
            background-color: transparent;
            color: var(--header-text-color);
            border: none;
            font-size: 24px;
            cursor: pointer;
            margin-right: 10px;
        }
        .toc-content {
            padding: 20px;
            overflow-y: auto;
            height: 100%;
        }
        .toc-content ul {
            list-style-type: none;
            padding-left: 0;
        }
        .toc-content li {
            margin-bottom: 10px;
        }
        .toc-content a {
            color: var(--text-color);
            text-decoration: none;
            transition: color 0.3s ease;
        }
        .toc-content a:hover {
            color: var(--color-primary);
        }
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            th, td {
                padding: 8px 10px;
            }
        }
        footer {
            background-color: var(--card-bg-color);
            color: var(--text-color);
            padding: 20px 0;
            border-top: 1px solid var(--border-color);
        }
        .footer-content {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
            text-align: center;
        }
        .footer-content p {
            margin: 5px 0;
        }
        .footer-content a {
            color: var(--color-primary);
        }
    </style>
    """


def html_js():
    """Java Script code for the html report"""

    return """
    <script>
    // Event listener for DOM content loaded
    document.addEventListener('DOMContentLoaded', () => {
        initializeTheme();
        setupCollapsibleSections();
        setupScrollToTop();
        setupContentMenuClose();
        setupEventListeners();
        initializeTables();
    });

    function initializeTheme() {
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.body.setAttribute('data-theme', savedTheme);
        updateThemeToggleIcon(savedTheme);
    }

    function setupEventListeners() {
        document.getElementById('theme-toggle').addEventListener('click', toggleTheme);
        document.getElementById("scrollToTop").addEventListener("click", scrollToTop);
        document.getElementById('toc-toggle').addEventListener('click', toggleTOC);

        document.querySelectorAll('#toc-sidebar a, #theme-toggle').forEach(element => {
            element.addEventListener('click', handleSidebarLinkClick);
        });
    }

    function initializeTables() {
        document.querySelectorAll('table').forEach(table => {
            updateRowStyles(table);
            updateFooter(table, '**', '');

            // Set up click listeners for all th elements
            table.querySelectorAll('th').forEach(th => {
                th.addEventListener('click', function() {
                    const columnIndex = this.cellIndex;
                    const type = this.getAttribute('data-type') || 'str'; // Get type from data attribute
                    sortTable(table, columnIndex, type);
                });
            });
        });

        // Set up search input listeners
        document.querySelectorAll('.searchInput').forEach(input => {
            input.addEventListener('input', handleSearchInput);
        });
    }

    function toggleTheme() {
        const body = document.body;
        const currentTheme = body.getAttribute('data-theme');
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        body.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        updateThemeToggleIcon(newTheme);
    }

    function updateThemeToggleIcon(theme) {
        const themeToggleIcon = document.getElementById('theme-toggle-icon');
        themeToggleIcon.textContent = theme === 'light' ? '☀️' : '🌙';
    }

    function updateRowStyles(table) {
        const visibleRows = Array.from(table.querySelectorAll('tbody tr'))
            .filter(row => row.style.display !== 'none');

        visibleRows.forEach((row, index) => {
            row.classList.toggle('odd-row', index % 2 === 0);
            row.classList.toggle('even-row', index % 2 !== 0);
        });
    }

    function searchTable(tableId) {
        const table = document.getElementById(tableId);
        const input = table.parentElement.querySelector('.searchInput');
        const filter = '*' + input.value.toLowerCase() + '*';
        const rows = table.querySelectorAll('tbody tr');
        let visibleCount = 0;
        let totals = Array(rows[0].cells.length - 1).fill(0);

        rows.forEach(row => {
            const cell = row.cells[0];
            const shouldDisplay = matchesFilter(cell.textContent, filter);

            row.style.display = shouldDisplay ? '' : 'none';
            if (shouldDisplay) {
                visibleCount++;
                for (let i = 1; i < row.cells.length; i++) {
                    totals[i - 1] += parseFloat(row.cells[i].textContent.replace(/,/g, '')) || 0;
                }
            }
        });

        updateTableVisibility(table, visibleCount);
        updateFooter(table, filter, totals);
        updateRowStyles(table);
    }

    function updateTableVisibility(table, visibleCount) {
        const noResultsMessage = table.parentElement.querySelector('.noResults');
        table.style.display = visibleCount === 0 ? 'none' : '';
        noResultsMessage.style.display = visibleCount === 0 ? 'block' : 'none';
    }

    function updateRowStyles(table) {
        const visibleRows = Array.from(table.querySelectorAll('tbody tr'))
            .filter(row => row.style.display !== 'none');

        visibleRows.forEach((row, index) => {
            row.classList.remove('odd-row', 'even-row');
            row.classList.add(index % 2 === 0 ? 'odd-row' : 'even-row');
        });
    }

    function matchesFilter(text, filter) {
        if (filter === '**') return true;

        const terms = filter.toLowerCase().split('*').filter(Boolean);
        let startIndex = 0;

        return terms.every(term => {
            const index = text.toLowerCase().indexOf(term, startIndex);
            if (index === -1) return false;
            startIndex = index + term.length;
            return true;
        });
    }

    function updateFooter(table, filter, totals) {
        const totalRow = table.querySelector('tfoot .total-row');
        const filteredTotalRow = table.querySelector('tfoot .filtered-total-row');

        if (filter === '**') {
            if (totalRow) totalRow.style.display = '';
            if (filteredTotalRow) filteredTotalRow.style.display = 'none';
        } else {
            if (totalRow) totalRow.style.display = 'none';
            if (filteredTotalRow) {
                filteredTotalRow.style.display = '';
    //            filteredTotalRow.querySelectorAll('td').forEach((cell, index) => {
    //                if (index > 0) {
    //                    cell.textContent = index === 3 ? formatSize(totals[index - 1]) : Math.round(totals[index - 1]);
    //                }
    //            });
            }
        }
    }

    function toggleTOC() {
        document.getElementById('toc-sidebar').classList.toggle('open');
    }

    function sortTable(table, columnIndex) {
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.rows).filter(row => row.style.display !== 'none');
        const th = table.querySelectorAll('th')[columnIndex];
        const dataType = th.getAttribute('data-type');

        // Determine the new sort direction
        let sortDirection = th.classList.contains('asc') ? 'desc' : 'asc';
        table.querySelectorAll('th').forEach(header => header.classList.remove('asc', 'desc'));
        th.classList.add(sortDirection);

        rows.sort((a, b) => {
            let aValue = a.cells[columnIndex].getAttribute('data-value') || a.cells[columnIndex].textContent.trim();
            let bValue = b.cells[columnIndex].getAttribute('data-value') || b.cells[columnIndex].textContent.trim();

            if (dataType === 'int' || dataType === 'size') {
                aValue = parseFloat(aValue);
                bValue = parseFloat(bValue);
            }

            if (sortDirection === 'asc') {
                return aValue < bValue ? -1 : aValue > bValue ? 1 : 0;
            } else {
                return bValue < aValue ? -1 : bValue > aValue ? 1 : 0;
            }
        });

        // Reorder the rows
        rows.forEach(row => tbody.appendChild(row));

        // Update row styles after sorting
        updateRowStyles(table);
    }

    function setupCollapsibleSections() {
        document.querySelectorAll('.info-section h2').forEach(header => {
            header.addEventListener('click', () => {
                const section = header.closest('.info-section');
                const content = section.querySelector('.section-content, .section-contenttab');
                const toggle = header.querySelector('.collapse-toggle');

                content.classList.toggle('collapsed');
                toggle.classList.toggle('collapsed');
                content.style.maxHeight = content.classList.contains('collapsed') ? '0' : content.scrollHeight + 'px';
            });
        });
    }

    function setupScrollToTop() {
        const scrollToTopButton = document.getElementById("scrollToTop");
        let lastScrollTop = 0;
        let isVisible = false;

        window.addEventListener('scroll', () => {
            const st = window.pageYOffset || document.documentElement.scrollTop;
            const shouldBeVisible = st > 300 && st < lastScrollTop;

            if (shouldBeVisible !== isVisible) {
                scrollToTopButton.style.display = shouldBeVisible ? 'block' : 'none';
                isVisible = shouldBeVisible;
            }

            lastScrollTop = st <= 0 ? 0 : st;
        });
    }

    function scrollToTop() {
        window.scrollTo({
            top: 0,
            behavior: "smooth"
        });
    }

    function setupContentMenuClose() {
        document.addEventListener('click', event => {
            const tocSidebar = document.getElementById('toc-sidebar');
            const tocToggle = document.getElementById('toc-toggle');

            if (tocSidebar.classList.contains('open') &&
                !tocSidebar.contains(event.target) &&
                event.target !== tocToggle) {
                tocSidebar.classList.remove('open');
            }
        });
    }

    function handleSearchInput(event) {
        const tableId = event.target.getAttribute('data-table');
        searchTable(tableId);
    }

    function handleColumnHeaderClick() {
        const table = this.closest('table');
        const columnIndex = this.cellIndex;
        const type = getColumnType(this);
        sortTable(table, columnIndex, type);
    }

    function handleSidebarLinkClick(e) {
        if (this.hash) {
            e.preventDefault();
            const targetId = this.hash.substring(1);
            const targetElement = document.getElementById(targetId);
            if (targetElement) {
                const headerOffset = document.querySelector('.sticky-header').offsetHeight;
                const elementPosition = targetElement.getBoundingClientRect().top;
                const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

                window.scrollTo({
                    top: offsetPosition,
                    behavior: "smooth"
                });
            }
        }
        document.getElementById('toc-sidebar').classList.remove('open');
    }

    function formatSize(bytes) {
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let size = bytes;
        let unitIndex = 0;
        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }
        return `${size.toFixed(2)} ${units[unitIndex]}`;
    }
    </script>
    """


def html_report(report, files_info, html_sections, html_toc):
    """
    Provides the complete HTML report output

    :param report: report dictionary
    :param files_info: files information
    :param html_sections: html code generated for the different sections
    :param html_toc: html code generated for the toc
    """

    logfile_content = ''
    dp_content = ''

    for file, timestamp, metrics, mtext, mcolor, mclass in files_info:
        logfile_content = f"""
                <span class="label">Analyzed File:</span>
                <span class="value">{os.path.basename(file)}</span>
                <span class="label">File Timestamp:</span>
                <span class="value">{timestamp}</span>
                <span class="label">Metrics:</span>
                <span class="value {mclass}">{mtext}</span>
        """
        dp_content = f"""
        <section id="data-processing" class="info-section">
            <h2><span class="collapse-toggle"></span>Data Processing</h2>
            <div class="section-content">
                <span class="label">Parallel workers:</span>
                <span class="value">{report['workers'] or "Not found"}</span>
                <span class="label">Schemas:</span>
                <span class="value">{report['schemas'] or "Not found"}</span>
                <span class="label">Objects:</span>
                <span class="value">{report['objects'] or "Not found"}</span>
                <span class="label">Data Objects:</span>
                <span class="value">{report['dobjects'] or "Not found"}</span>
                <span class="label">Overall Size:</span>
                <span class="value">{report['totalsize'] or "Not found"}</span>
            </div>
        </section>
        """

    return f"""
    {html_head()}
    <body data-theme="light">
    <svg style="display: none;">
      <symbol id="collapse-icon" viewBox="0 0 24 24">
        <circle cx="12" cy="12" r="10" fill="none" stroke="#666" stroke-width="2"/>
        <path d="M8 12l4 4 4-4" fill="none" stroke="#666" stroke-width="2"/>
      </symbol>
    </svg>
    <noscript>
        <div class="container">
          <div class="no-js">
            JavaScript is disabled. Some features of this report, including collapsible sections, sorting and searching, will not work.
          </div>
        </div>
    </noscript>

    <nav id="toc-sidebar" class="toc-sidebar">
        <div class="toc-content">
            <h2>Contents</h2>
            <ul>
                <li><a href="#dpla-details">DPLA Report Details</a></li>
                <li><a href="#logfile-details">Logfile Details</a></li>
                <li><a href="#operation-details">Operation Details</a></li>
                <li><a href="#data-processing">Data Processing</a></li>
            </ul>
            <hr>
            <ul>
                {html_toc}
            </ul>
            <hr>
            <button id="theme-toggle" aria-label="Toggle Dark Mode">
                <span id="theme-toggle-icon">☀️</span>
            </button>
        </div>
    </nav>

    <header class="sticky-header">
        <button id="toc-toggle" class="toc-toggle" aria-label="Toggle Table of Contents">☰</button>
        <h1>Data Pump Log Analyzer</h1>
    </header>

    <main class="container">
        <section id="dpla-details" class="info-section">
            <h2><span class="collapse-toggle"></span>DPLA Report Details</h2>
            <div class="section-content">
                <span class="label">Version:</span>
                <span class="value">{report['version']}</span>
                <span class="label">Arguments:</span>
                <span class="value">{report['argslist']}</span>
                <span class="label">Generated:</span>
                <span class="value">{report['generated']}</span>
            </div>
        </section>

        <section id="logfile-details" class="info-section">
            <h2><span class="collapse-toggle"></span>Logfile Details</h2>
            <div class="section-content">
                {logfile_content}
            </div>
        </section>

        <section id="operation-details" class="info-section">
            <h2><span class="collapse-toggle"></span>Operation Details</h2>
            <div class="section-content">
                <span class="label">Operation:</span>
                <span class="value">{report['operation'] or "Not found"}</span>
                <span class="label">DP Version:</span>
                <span class="value">{report['dpversion'] or "Not found"}</span>
                <span class="label">DB Info:</span>
                <span class="value">{report['dbinfo'] or "Not found"}</span>
                <span class="label">Job Name:</span>
                <span class="value">{report['jobname'] or "Not found"}</span>
                <span class="label">Status:</span>
                <span class="value {report['opclass']}">{report['opstatus'] or "Not found"}</span>
                <span class="label">&nbsp&nbspProcessing:</span>
                <span class="value">{report['processing']}</span>
                <span class="label">Errors:</span>
                <span class="value {report['errclass']}">{report['errors']}</span>
                <span class="label">&nbsp&nbspORA- Messages:</span>
                <span class="value {report['oraclass']}">{report['oramsgs']}</span>
                <span class="label">Start Time:</span>
                <span class="value">{report['starttime'] or "Not found"}</span>
                <span class="label">End Time:</span>
                <span class="value">{report['endtime'] or "Not found"}</span>
                <span class="label">Runtime:</span>
                <span class="value">{report['runtime'] or "Not found"}</span>
            </div>
        </section>
        {dp_content}
        {html_sections}
    </main>
    <button id="scrollToTop" title="Go to top">
        <span class="arrow"></span>
    </button>

    {html_js()}

    </body>
    <footer>
        <div class="footer-content">
            <p>Data Pump Log Analyzer v{__version__}</p>
            <p>Copyright &copy; 2024 <a href="https://github.com/macsdata">macsdata</a></p>
        </div>
    </footer>
    </html>
    """


def html_table(headers, rows, alignments, summary=None, tabname=None):
    """
    Generate an HTML table from headers, rows, and alignments.

    :param headers: List of header titles
    :param rows: List of row data (each row is a list of values)
    :param alignments: List of alignments for each column ('<' for left, '>' for right)
    :param summary: List of summary values
    :param tabname: Table Name
    """
    # Start the HTML table
    html_output = f'\n<table id="{tabname}">\n'

    # Add headers
    html_output += '    <thead>\n        <tr>\n'
    for idx, header in enumerate(headers):
        if alignments[idx] == '<':
            datatype = ' data-type="str"'
            align = ' class="text-column"'
        else:
           datatype = ' data-type="int"'
           align = ''
        html_output += f"           <th{datatype}{align}>{header}<span class=\"sort-icons\"></span></th>\n"
    html_output += '        </tr>\n    </thead>\n'

    # Add rows
    html_output += '    <tbody>\n'
    for row in rows:
        html_output += '        <tr>'
        for idx, item in enumerate(row):
            align = ' class="text-column"' if alignments[idx] == '<' else ''
            if isinstance(item, tuple):
                # Store the MB value with the data-value label
                formatted_size, original_mb = item
                html_output += f'<td{align} data-value="{original_mb}">{formatted_size}</td>'
            else:
                html_output += f'<td{align}>{item}</td>'
        html_output += '</tr>\n'
    html_output += '    </tbody>\n'

    # Add summary if present
    html_output += '    <tfoot>\n'
    if summary:
        html_output += '        <tr class=\"total-row\">'
        for idx, item in enumerate(summary):
            align = ' class="text-column"' if alignments[idx] == '<' else ''
            html_output += f'<td{align}>{item}</td>'
        html_output += '</tr>\n'
    html_output += '    </tfoot>\n'

    # Close the table
    html_output += '</table>'
    return html_output


def html_section(args, section, sectitle, colname, stats, filter=None):
    """
    Generate html code for a section based on the stats data structure.

    :param args: script arguments provided
    :param section: the name of the section (e.g., 'worker', 'object').
    :param sectitle: the title of the section
    :param colname: the name of the first column in the table
    :param stats: stats data for the section
    :param filter: argument specified filter
    """

    sort = args.sort if args.sort else defaults[section]['sort']

    if (isinstance(filter, list) and len(filter) > 0):
        pmesg(f"Filter {filter} will be ignored.", 'info')
    filtered_stats = stats

    sorted_rows, actual_sort = safe_sort(filtered_stats, sort, colname, section)
    final_rows = sorted_rows

    tabname = f'tab-{section}'
    html_toc = f'<li><a href="#sec-{section}">{sectitle.title()}</a></li>\n'
    html_section = f"""
    <section id="sec-{section}" class="info-section">
        <h2><span class="collapse-toggle"></span>{sectitle.title()}</h2>
        <div class="section-contenttab">
            <div class="search-container">
                <input type="text" class="searchInput" id="input{tabname}" data-table="{tabname}" placeholder="Search for {colname.title()}...">
            </div>
            <div class="noResults">No results found.</div>
    """

    # Assume all items have the same keys, use the first item to determine fields
    if final_rows:
        fields = list(final_rows[0][1].keys())  # Dynamically get fields from the stats dictionary
        headers = [colname.title()] + [field.capitalize() for field in fields]
        alignments = ['<'] + ['>' for _ in fields]

        # Calculate totals
        # Initialize totals with appropriate starting values
        totals = {field: 0 if aggr_methods.get(field, aggr_default) == sum else float('-inf') for field in fields}

        for _, stat in final_rows:
            for field in totals:
                value = stat.get(field, 0)  # Get the value safely
                if isinstance(value, (int, float)):  # Check if the value is numeric
                    agg_func = aggr_methods.get(field, aggr_default)  # Get the appropriate aggregation function
                    if agg_func == sum:
                        totals[field] += value
                    elif agg_func == max:
                        totals[field] = max(totals[field], value)
                elif value == 'N/A':
                    totals[field] = ''

        # Prepare rows for table
        rows = []
        for row in final_rows:
            formatted_row = [row[0]]  # First column (usually the name or identifier)
            for field in fields:
                if field == 'size':
                    size_mb = row[1][field]  # Original size in MB
                    formatted_size = format_size(size_mb)
                    formatted_row.append((formatted_size, size_mb))  # Tuple of (formatted_size, original_mb)
                else:
                    formatted_row.append(row[1][field])
            rows.append(formatted_row)

        # Prepare summary
        summary = ["Total"] + [
            format_size(totals[field]) if field == 'size' else totals[field] for field in fields
        ]

        html_section += html_table(headers, rows, alignments, summary, tabname)

    html_section += """
        </div>
    </section>
    """
    return html_section, html_toc


def main():

    args, toprows = parse_arguments()
    if args.output:
        outformat = get_extension(args.output)
    else:
        outformat = None

    argslist = ", ".join([
        f"{k}={v}" for k, v in vars(args).items()
        # Exclude all default, unset and files parameters
        # if v not in [False, None] and k != 'files'
        if v not in [False, None] and k != 'file'
    ])

    """
    #### Preparation multiple files input
    # Validate the files and enforce maximum of two files
    if len(args.files) > 2:
        print("Error: You can only specify up to two files.", file=sys.stderr)
        sys.exit(1)
    files_valid = validate_files(args.files)
    """

    # Validate input file
    files_valid = validate_files(args.file)

    # Initialize variable for report
    files_info = []
    report = {
        'version': __version__,
        'argslist': argslist,
        'generated': datetime.now().strftime('%a %b %d %H:%M:%S %Y'),
        'operation': '',
        'dpversion': '',
        'dbinfo': '',
        'jobname': '',
        'opstatus': 'RUNNING / TERMINATED',
        'opcolor': Colors.YELLOW,
        'opclass': 'highlight warn',
        'processing': '',
        'errors': '',
        'errcolor': Colors.GREEN,
        'errclass': '',
        'oramsgs': 0,
        'oracolor': Colors.GREEN,
        'oraclass': 'highlight ok',
        'starttime': '',
        'endtime': '',
        'runtime': '',
        'workers': 0,
        'schemas': 0,
        'objects': 0,
        'dobjects': 0,
        'totalsize_mb': 0,
        'totalsize': 0,
    }

    # Read and process the file
    for filepath, filets in files_valid:
        with open(filepath, "r") as file_handle:
            for line in file_handle:
                # Get operation and startime
                if not report['operation']:
                    operation_match = operation_re.search(line)
                    if operation_match:
                        report['operation'] = operation_match.group('operation')
                        report['starttime'] = datetime.strptime(operation_match.group('starttime'), '%a %b %d %H:%M:%S %Y')

                # Get jobname
                if not report['jobname']:
                    jobname_match = jobname_re.search(line)
                    if jobname_match:
                        report['jobname'] = jobname_match.group('jobname')

                # Get startime for reports without operation (API,ZDM)
                if not report['starttime']:
                    starttime_match = starttime_re.search(line)
                    if starttime_match:
                        try:
                            report['starttime'] = datetime.strptime(starttime_match.group('starttime'), '%d-%b-%y %H:%M:%S')
                        except ValueError:
                            pass

                # Get Data Pump client version
                if not report['dpversion']:
                    dpversion_match = dpversion_re.search(line)
                    if dpversion_match:
                        report['dpversion'] = dpversion_match.group('dpversion')

                # Get DB info
                if "Connected to" in line:
                    if not report['dbinfo']:
                        dbinfo_match = dbinfo_re.search(line)
                        if dbinfo_match:
                            report['dbinfo'] = dbinfo_match.group('dbinfo')

                # Get endtime and errors if operation is completed
                if "completed" in line:
                    endtime_match = endtime_re.search(line)
                    if endtime_match:
                        report['endtime'] = datetime.strptime(endtime_match.group('endtime'), '%a %b %d %H:%M:%S %Y')
                        try:
                            report['runtime'] = str(report['endtime'] - report['starttime']).split('.')[0]
                        except TypeError:
                            pass
                        report['errors'] = endtime_match.group('errors') if endtime_match.group('errors') else 0
                        if report['errors'] != 0:
                            report['errcolor'] = Colors.RED
                            report['errclass'] = 'highlight fail'
                        elif report['errors'] == 0:
                            report['errclass'] = 'highlight ok'
                        report['opstatus'] = "COMPLETED"
                        report['opcolor'] = Colors.GREEN
                        report['opclass'] = 'highlight ok'

                # Get worker information
                if "Startup" in line:
                    worker_match = worker_re.search(line)
                    if worker_match:
                        wm_worker = worker_match.group("worker")
                        # wm_workerid = int(wm_worker.split('-')[1])
                        wm_workerid = int(wm_worker)
                        # wm_instance = worker_match.group("instance") if worker_match.group('instance') else "N/A"
                        wm_instance = int(worker_match.group("instance")) if worker_match.group('instance') else "N/A"
                        report['workers'] = max(report['workers'], wm_workerid)
                        worker_stats[wm_worker]['instance'] = wm_instance

                # Get ORA- messages
                if "ORA-" in line:
                    oramsg_match = oramsg_re.search(line)
                    if oramsg_match:
                        cleaned_errors = clean_error_messages(oramsg_match.group(0), oramsg_delpattern)
                        oramsg_stats[cleaned_errors]['count'] += 1
                        report['oramsgs'] += 1
                        report['oracolor'] = Colors.RED
                        report['oraclass'] = 'highlight fail'

                # Get last processing state
                if "Processing" in line:
                    otype_match = otype_re.search(line)
                    if otype_match:
                        report['processing'] = otype_match.group('otype')

                # Get data load information
                data_match = data_re.search(line)
                if data_match:
                    dm_worker = data_match.group("worker")
                    dm_operation = data_match.group("operation")
                    dm_schema = data_match.group("schema")
                    dm_table = data_match.group("table")
                    dm_partition = data_match.group("partition") if 'partition' in data_match.groupdict() else None
                    dm_subpartition = data_match.group("subpartition") if 'subpartition' in data_match.groupdict() else None
                    dm_size = float(data_match.group("size"))
                    dm_unit = data_match.group("unit")
                    dm_rows = int(data_match.group("rows"))
                    dm_seconds = int(data_match.group('seconds')) if 'seconds' in data_match.groupdict() else 0

                    # Convert to MB
                    if dm_unit == "KB":
                        size_mb = float(dm_size) / 1024
                    elif dm_unit == "MB":
                        size_mb = float(dm_size)
                    elif dm_unit == "GB":
                        size_mb = float(dm_size) * 1024
                    elif dm_unit == "TB":
                        size_mb = float(dm_size) * 1024 * 1024

                    if not report['operation']:
                        report['operation'] = dm_operation[:-2].title()
                    report['dobjects'] += 1
                    report['totalsize_mb'] += size_mb

                    worker_stats[dm_worker]['objects'] += 1
                    worker_stats[dm_worker]['size'] += size_mb
                    worker_stats[dm_worker]['seconds'] += dm_seconds

                    schema_stats[dm_schema]['objects'] += 1
                    schema_stats[dm_schema]['size'] += size_mb
                    schema_stats[dm_schema]['seconds'] += dm_seconds

                    table_key = f"{dm_schema}.{dm_table}"
                    table_stats[table_key]["rows"] += dm_rows
                    table_stats[table_key]["size"] += size_mb
                    table_stats[table_key]["seconds"] += dm_seconds

                    if dm_partition:
                        table_stats[table_key]["part"].add(dm_partition)
                    if dm_subpartition:
                        table_stats[table_key]["subpart"] += 1

                # Get object type information
                if "Completed" in line:
                    object_match = object_re.search(line)
                    if object_match:
                        om_count = int(object_match.group("ocount"))
                        om_type = object_match.group("otype")
                        om_worker = object_match.group("worker")
                        om_seconds = int(object_match.group("seconds"))

                        if om_worker is None:
                            object_stats[om_type]['count'] += om_count
                            object_stats[om_type]['duration'] += om_seconds
                            report['objects'] += om_count
                        else:
                            object_stats[om_type]['seconds'] += om_seconds
                            object_stats[om_type]['workers'].add(om_worker) 

        dict_list = ['worker_stats', 'object_stats']
        fresult = file_valid(report)
        mresult = file_metrics(dict_list)

        if not fresult['valid']:
            # vars_unset = ', '.join([item.replace('_', ' ').title() for item in fresult['vars_unset']])
            # pmesg(f"No information found for: {vars_unset}",'info')

            bf_continue = input(f"The provided file does not look like a Data Pump logfile. Continue? (y/n): ").strip().lower()
            if bf_continue != 'y':
                pmesg("Operation aborted.", 'info', 1)

        if not mresult['valid']:
            # empty_dicts = ', '.join([item.replace('_stats', '').replace('_', ' ').title() for item in mresult['empty_dicts']])
            # pmesg(f"No statistics collected for: {empty_dicts}",'info')
            pmesg(f"Limited Output. Make sure METRICS=YES is specified for Data Pump operations", 'info')
            files_info.append((filepath, filets, False, 'False', Colors.YELLOW, 'highlight warn'))
        else:
            files_info.append((filepath, filets, True, 'True', '', ''))

    # Calculate Report Variables
    report['schemas'] = len(schema_stats)
    if report['totalsize_mb']:
        report['totalsize'] = format_size(report['totalsize_mb'])
    if report['opstatus'] == 'COMPLETED':
        report['processing'] = '-'
    else:
        try:
            report['runtime'] = str(datetime.now() - report['starttime']).split('.')[0]
        except TypeError:
            pass

    # Aggregate data by instance
    for worker, data in worker_stats.items():
        instance_id = data['instance']
        instance_stats[instance_id]['workers'].add(worker)
        instance_stats[instance_id]['objects'] += data['objects']
        instance_stats[instance_id]['size'] += data['size']
        instance_stats[instance_id]['seconds'] += data['seconds']

    # Convert sets of workers to counts of workers for final output
    for instance in instance_stats:
        instance_stats[instance]['workers'] = len(instance_stats[instance]['workers'])

    # Convert partitions into partition count
    for table in table_stats:
        table_stats[table]['part'] = len(table_stats[table]['part'])

    # Convert workers into workers_count
    for obj in object_stats:
        object_stats[obj]['workers'] = len(object_stats[obj]['workers']) or 1
        if object_stats[obj]['seconds'] == 0:
            object_stats[obj]['seconds'] = object_stats[obj]['duration']

    for obj_type, stats in object_stats.items():
        if obj_type.endswith("TABLE_DATA"):
            # Set the number of workers to the count of unique worker IDs stored in worker_stats
            stats['workers'] = len(worker_stats)

    # Set table filter if schemas are filtered and no table filter is specified
    if args.schema and args.table == []:
        # Specific schemas are listed and used for the table filter
        tableargs = [k + "." for k in schema_stats.keys() if any(f.upper() in k.upper() for f in args.schema)]
    else:
        tableargs = args.table

    # Report Output
    sections = [
        ('oramsg', 'ora- messages details', 'message', oramsg_stats, args.error),
        ('object', 'object details', 'object', object_stats, args.object),
        ('worker', 'worker details', 'worker', worker_stats, args.worker),
        ('schema', 'schema details', 'schema', schema_stats, args.schema),
        ('table', 'table details', 'table', table_stats, tableargs),
        ('instance', 'instance details', 'instance', instance_stats, args.instance)
    ]

    if outformat == 'html':
        html_sections = ''
        html_toc = ''

        for section_id, section_title, colname, section_stats, section_filter in sections:
            if args.all or section_filter or (isinstance(section_filter, list) and len(section_filter) >= 0):
                html_part, toc_part = html_section(args, section_id, section_title, colname, section_stats, section_filter)
                html_sections += html_part
                html_toc += toc_part
        if args.top:
            pmesg(f"--top {args.top} will be ignored.", 'info')

        with OutputRedirector(args.output):
            print(html_report(report, files_info, html_sections, html_toc))

    else:
        with OutputRedirector(args.output):
            print_report(report, files_info)
            for section_id, section_title, colname, section_stats, section_filter in sections:
                if args.all or section_filter or (isinstance(section_filter, list) and len(section_filter) >= 0):
                    print_section(args, toprows, section_id, section_title, colname, section_stats, section_filter)


if __name__ == "__main__":
    main()
