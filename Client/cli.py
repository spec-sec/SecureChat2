import curses
from Client.client import Client
from typing import Optional, List, Dict
from .chat import ChatManager, Message, Session


class KEYS:

    BACKSPACE = [curses.KEY_BACKSPACE, curses.KEY_DC, 127]
    TAB = [9]
    ENTER = [curses.KEY_ENTER, 10, 13]
    ESC = [27]


class CLI:

    def __init__(self, stdscr, client: Client):

        self.stdscr = stdscr
        self.client = client
        self.max_y, self.max_x = self.stdscr.getmaxyx()
        self.mid_y = self.max_y // 2
        self.mid_x = self.max_x // 2
        self.container = curses.newwin(self.max_y - 1, self.max_x, 1, 0)
        self.initial_setup()
        self.login_setup()
        self.chat_manager = ChatManager(self.client)
        sessions_list = list(self.chat_manager.sessions.values())
        self.selected_session = None
        self.client.listener.set_interface(self)
        while True:
            self.sessions_setup(sessions_list)
            selected = self.sessions_loop(sessions_list)
            if selected is None:
                break
            self.selected_session = sessions_list[selected]
            self.message_setup(self.selected_session)
        self.clean_exit()

    def initial_setup(self):
        """
        Perform basic command-line interface initial_setup.
        """
        curses.curs_set(1)
        curses.noecho()
        curses.cbreak()
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        self.stdscr.clear()
        self.stdscr.addstr("SecureChat v2")
        self.container.box()
        self.refresh_all()

    def login_setup(self):
        self.container.addstr(self.mid_y - 4, self.mid_x - 3, "Log In")
        self.refresh_all()
        username_win = curses.newwin(3, self.mid_x, self.mid_y - 2, self.mid_x // 2)
        password_win = curses.newwin(3, self.mid_x, self.mid_y + 1, self.mid_x // 2)
        self.init_input(password_win, "Password")
        self.init_input(username_win, "Username")
        username = self.get_input(username_win, "Username")
        password = self.get_input(password_win, "Password", hide=True)
        self.client.login(username, password)

    def sessions_setup(self, sessions_list: List[Session], selected=0):
        curses.curs_set(0)
        self.container.clear()
        self.container.box()
        self.container.addstr(1, self.mid_x - 7, "Chat Sessions")
        for idx, session in enumerate(sessions_list):
            if idx == selected:
                self.container.addstr(2 + idx, 2, str(session), curses.A_STANDOUT)
            else:
                self.container.addstr(2 + idx, 2, str(session))
        self.refresh_all()

    def sessions_loop(self, sessions_list: List[Session]) -> Optional[int]:
        selected = 0
        num_sessions = len(self.chat_manager.sessions)
        while True:
            c = self.stdscr.getch()
            if c == curses.KEY_UP:
                selected = max(0, selected - 1)
                self.sessions_setup(sessions_list, selected)
            elif c == curses.KEY_DOWN:
                selected = min(num_sessions - 1, selected + 1)
                self.sessions_setup(sessions_list, selected)
            elif c in KEYS.ENTER:
                return selected
            elif c in KEYS.ESC:
                return None

    def message_setup(self, session: Session):
        if len(session.messages) == 0:
            session.get_messages()
        self.container.clear()
        self.container.box()
        max_y, max_x = self.container.getmaxyx()
        msg_max_x = max_x - 4
        session_title = str(session)
        self.container.addstr(1, max_x // 2 - (len(session_title) // 2), session_title)
        offset = 3
        for idx, msg in enumerate(session.messages):
            offset += self.add_msg(msg, idx, offset, msg_max_x)
        session.offset = offset
        msg_input_win = curses.newwin(3, max_x - 4, max_y - 3, 2)
        self.refresh_all()
        self.init_input(msg_input_win, "Message")
        curses.curs_set(1)
        while True:
            msg_input = self.get_input(msg_input_win, "Message")
            if not msg_input:
                break
            session.send_msg(msg_input)
            self.add_msg(session.messages[-1], len(session.messages) - 1, offset, msg_max_x)
            session.offset += 1
            self.refresh_all()
            self.init_input(msg_input_win, "Message")

    def add_msg(self, msg: Message, msg_index: int, offset: int, max_len: int) -> int:
        msg_string = str(msg)
        msg_parts = [msg_string[i:i+max_len] for i in range(0, len(msg_string), max_len)]
        for part_index, line in enumerate(msg_parts):
            if msg.sender.id == self.client.user_id:
                color_pair = 2
            else:
                color_pair = 1
            self.container.addstr(offset + msg_index + part_index, 2,
                                  line, curses.color_pair(color_pair))
        return len(msg_parts) - 1

    def listener_add_msg(self, msg_dict: Dict):
        session = self.chat_manager.sessions.get(msg_dict['session'])
        session.add_msg(msg_dict['content'], msg_dict['time_sent'])
        if self.selected_session.id == session.id:
            session.offset += self.add_msg(session.messages[-1],
                                           len(session.messages) - 1,
                                           session.offset,
                                           self.container.getmaxyx()[1] - 4)
            self.refresh_all()
            # TODO: move cursor back to input
        else:
            # TODO: add notification
            pass

    @staticmethod
    def init_input(win, prompt: str, default_input=""):
        win.clear()
        win.box()
        win.addstr(0, 1, " " + prompt + " ")
        win.addstr(1, 2, default_input, curses.color_pair(2))
        win.refresh()

    @staticmethod
    def focus_input(win):
        win.addstr(1, 2, "")
        win.refresh()

    def get_input(self, win, prompt: str, hide=False) -> Optional[str]:
        """
        Main input loop.
        """
        win_max_x = win.getmaxyx()[1]
        self.focus_input(win)
        inp = ""
        inp_color = curses.color_pair(2)
        while True:
            # Get input character
            c = self.stdscr.getch()
            # Enter submits the message
            if c in KEYS.ENTER or c in KEYS.TAB:
                if len(inp) > 0:
                    return inp
                else:
                    continue
            elif c in KEYS.ESC:
                return None
            # Delete last character
            elif c in KEYS.BACKSPACE:
                inp = inp[:-1]
                if hide:
                    default_inp = "*" * len(inp)
                else:
                    default_inp = inp
                self.init_input(win, prompt, default_input=default_inp)
            # Add input to message if it doesn't exceed max length
            elif len(inp) < win_max_x - 4:
                k = chr(c)
                inp += k
                if hide:
                    win.addstr("*", inp_color)
                else:
                    win.addstr(k, inp_color)
                win.refresh()

    def refresh_all(self):
        """
        Refresh everything in the interface.
        """
        self.stdscr.noutrefresh()
        self.container.noutrefresh()
        curses.doupdate()

    def clean_exit(self):
        """
        Exit cleanly from the interface and reset the command line.
        """
        self.client.stop()
        self.stdscr.keypad(False)
        curses.echo()
        curses.nocbreak()
        curses.endwin()
