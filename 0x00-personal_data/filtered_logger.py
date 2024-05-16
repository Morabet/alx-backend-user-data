#!/usr/bin/env python3
""" Regex-ing"""


import logging
import os
import mysql.connector
import re
from typing import List


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    '''returns the log message obfuscated:'''
    pattern = "|".join(fields)
    return re.sub(
        fr'({pattern})=([^{separator}]+)', f'\\1={redaction}', message
    )


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        '''initializing the instance'''
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        '''formatting record'''
        filtered_message = filter_datum(
            self.fields, self.REDACTION, record.getMessage(), self.SEPARATOR)
        record.msg = filtered_message
        return super().format(record)


def get_logger() -> logging.Logger:
    """
    the use of this function is to create a logging object
    and add to it our custom formatter
    """

    # Create a logger named "user_data"
    logger = logging.getLogger('user_data')
    # Set the logging level to INFO
    logger.setLevel(logging.INFO)
    # Prevent propagation of messages to other loggers
    logger.propagate = False
    # Create a StreamHandler
    stream_handler = logging.StreamHandler()
    # Create a RedactingFormatter
    formatter = RedactingFormatter(fields=PII_FIELDS)
    # Set the formatter for the StreamHandler
    stream_handler.setFormatter(formatter)
    # Add the StreamHandler to the logger
    logger.addHandler(stream_handler)

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """Connect to the MySQL database and return the connection object."""

    connection = mysql.connector.connect(
        host=os.getenv('PERSONAL_DATA_DB_HOST', 'localhost'),
        port=3306,
        user=os.getenv('PERSONAL_DATA_DB_USERNAME', 'root'),
        password=os.getenv('PERSONAL_DATA_DB_PASSWORD', ''),
        database=os.getenv('PERSONAL_DATA_DB_NAME', '')
    )
    return connection


def main() -> None:
    """ main function"""

    logger = get_logger()
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    field_names = [i[0] for i in cursor.description]
    for row in cursor:
        str_row = ''.join(f'{f}={str(r)}; ' for r, f in zip(row, field_names))
        logger.info(str_row.strip())
    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
