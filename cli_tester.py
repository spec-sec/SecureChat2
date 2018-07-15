import curses
from Client.cli import CLI
from Client.client import Client


def main(stdscr):
    client = Client("127.0.0.1")
    cli = CLI(stdscr, client)


curses.wrapper(main)
