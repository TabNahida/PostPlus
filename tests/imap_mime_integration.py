#!/usr/bin/env python3
"""Strict IMAP metadata grammar and mobile-style MIME section downloads."""
import argparse
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
import secrets

from integration import PASSWORD, ROOT, Suite
from imap_clients_integration import Wire
from mail_clients_integration import wait_tls


@dataclass
class Value:
    data: object
    start: int
    end: int


class ResponseParser:
    """Parse nstrings, including literals, without accepting 8-bit quotes."""
    def __init__(self, raw):
        self.raw, self.at = raw, 0

    def value(self):
        start, raw = self.at, self.raw
        if raw[self.at] == ord('('):
            self.at += 1
            children = []
            while raw[self.at] != ord(')'):
                if raw[self.at] == ord(' '):
                    self.at += 1
                    continue
                children.append(self.value())
            self.at += 1
            return Value(children, start, self.at)
        if raw[self.at] == ord('"'):
            self.at += 1
            text = bytearray()
            while raw[self.at] != ord('"'):
                byte = raw[self.at]
                assert 0 < byte < 128 and byte not in (10, 13), 'IMAP4rev1 quoted string contains an 8-bit/control byte'
                self.at += 1
                if byte == ord('\\'):
                    byte = raw[self.at]
                    self.at += 1
                text.append(byte)
            self.at += 1
            return Value(bytes(text), start, self.at)
        if raw[self.at] == ord('{'):
            end = raw.index(b'}\r\n', self.at)
            count = int(raw[self.at + 1:end])
            self.at = end + 3 + count
            return Value(raw[end + 3:self.at], start, self.at)
        brackets = 0
        while self.at < len(raw) and (brackets or raw[self.at] not in b' ()\r\n'):
            if raw[self.at] == ord('['):
                brackets += 1
            elif raw[self.at] == ord(']'):
                brackets -= 1
            self.at += 1
        token = raw[start:self.at]
        return Value(None if token == b'NIL' else int(token) if token.isdigit() else token, start, self.at)


def fetch_values(wire, command):
    raw = wire.command('fetch', 'FETCH 1 ' + command)
    parser = ResponseParser(raw)
    parser.at = raw.index(b' FETCH (') + len(b' FETCH ')
    parsed = parser.value().data
    return raw, {parsed[index].data: parsed[index + 1] for index in range(0, len(parsed), 2)}


def values(node):
    return [value.data for value in node.data]


def check_body_grammar(raw, node):
    fields = node.data
    assert fields and isinstance(fields, list)
    if isinstance(fields[0].data, list):
        index = 0
        while index < len(fields) and isinstance(fields[index].data, list):
            check_body_grammar(raw, fields[index])
            if index:
                assert raw[fields[index - 1].end:fields[index].start] == b'', 'multipart children must be adjacent per RFC 3501'
            index += 1
        assert raw[fields[index - 1].end:fields[index].start] == b' '
        assert isinstance(fields[index].data, bytes)
    elif fields[0].data == b'MESSAGE' and fields[1].data == b'RFC822':
        assert len(fields[7].data) == 10, 'embedded message envelope must have ten fields'
        check_body_grammar(raw, fields[8])


def run(s):
    s.config.update(tls_certificate=str(ROOT / 'tests/fixtures/localhost-test-only.crt'),
                    tls_private_key=str(ROOT / 'tests/fixtures/localhost-test-only.key'),
                    allow_insecure_auth=False, max_connections=16, max_message_bytes=65536)
    s.save()
    for service in ('auth', 'storage', 'imap'):
        s.start(service)
    wait_tls(s, 'imaps')
    user = 'imap-mime@localhost'
    assert s.rpc('auth', op='create', username=user, password=PASSWORD)['ok']
    prefix = (b'From: sender@example.net (Sender Name)\r\n'
              b'To: Team: imap-mime@localhost, "Quoted\\\" Name" <other@example.net>;\r\n')
    plain = b'Content-Type: text/plain; charset=utf-8\r\n\r\nplain body\r\n'
    samples = {
        'utf8': ('From: "发送人" <sender@example.net>\r\nTo: imap-mime@localhost\r\nSubject: 中文主题\r\n'.encode() + plain),
        'utf8-attachment': prefix + b'Subject: Unicode filename\r\n' +
            'Content-Type: application/octet-stream; name="附件.bin"\r\nContent-Disposition: attachment; filename="附件.bin"\r\n\r\n'.encode() + b'attachment body\r\n',
        'quoted-address': b'From: "Sender <Name>" <"odd@box"@example.net>\r\n' + prefix.split(b'\r\n', 1)[1]
            + b'Subject: quoted address\r\n' + plain,
        'alternative': prefix + b'Subject: multipart\r\nContent-Type: multipart/alternative; boundary=b\r\n\r\n'
            b'--b\r\nContent-Type: text/plain\r\n\r\nplain body\r\n'
            b'--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>html body</p>\r\n--b--\r\n',
        'quoted-printable': prefix + b'Subject: readable metadata\r\nContent-Type: text/plain\r\n'
            b'Content-Transfer-Encoding: quoted-printable\r\n\r\ncost = 5\r\n',
        'extension-encoding': prefix + b'Subject: opaque encoding\r\nContent-Type: application/octet-stream\r\n'
            b'Content-Transfer-Encoding: x-local\r\n\r\nopaque body\r\n',
        'forwarded': prefix + b'Subject: forwarded\r\nContent-Type: message/rfc822\r\n\r\n'
            + prefix + b'Subject: embedded\r\nContent-Type: text/plain\r\n\r\n' + b'x' * 40000 + b'\r\n',
    }
    for folder, message in samples.items():
        assert len(message) < s.config['max_message_bytes']
        assert s.rpc('storage', op='folder_create', username=user, folder=folder)['ok']
        assert s.rpc('storage', op='append', username=user, folder=folder, raw=message)['ok']
        with closing(Wire(s)) as wire:
            wire.login(user)
            wire.command('select', 'SELECT "' + folder + '"')
            raw, metadata = fetch_values(wire, '(UID ENVELOPE BODYSTRUCTURE)')
            envelope = metadata[b'ENVELOPE'].data
            assert len(envelope) == 10
            check_body_grammar(raw, metadata[b'BODYSTRUCTURE'])
            if folder == 'utf8':
                assert envelope[1].data == '中文主题'.encode()
                assert envelope[2].data[0].data[0].data == '发送人'.encode()
                assert b'"\xe4\xb8\xad' not in raw, 'UTF-8 metadata was sent in an illegal quoted string'
            else:
                expected_sender = ([b'Sender <Name>', None, b'odd@box', b'example.net'] if folder == 'quoted-address'
                                   else [b'Sender Name', None, b'sender', b'example.net'])
                assert values(envelope[2].data[0]) == expected_sender
                assert values(envelope[5].data[0]) == [None, None, b'Team', None]
                assert values(envelope[5].data[-1]) == [None, None, None, None]
                assert envelope[5].data[2].data[0].data == b'Quoted" Name'
            _, complete = fetch_values(wire, '(BODY.PEEK[])')
            assert complete[b'BODY[]'].data == message
            _, part = fetch_values(wire, '(BODY.PEEK[1])')
            expected = (b'plain body' if folder == 'alternative' else message.split(b'\r\n\r\n', 1)[1])
            assert part[b'BODY[1]'].data == expected
            # Mobile clients download MIME sections in bounded byte ranges.
            _, partial = fetch_values(wire, '(BODY.PEEK[1]<2.5>)')
            assert partial[b'BODY[1]<2>'].data == expected[2:7]
            if folder == 'forwarded':
                _, nested = fetch_values(wire, '(BODY.PEEK[1.HEADER.FIELDS (SUBJECT)] BODY.PEEK[1.1]<3.7>)')
                assert nested[b'BODY[1.HEADER.FIELDS (SUBJECT)]'].data == b'Subject: embedded\r\n\r\n'
                assert nested[b'BODY[1.1]<3>'].data == b'x' * 7
            assert not s.rpc('storage', op='list', username=user, folder=folder)['messages'][0]['seen']
    # ENVELOPE must not parse the MIME body at all. This remains readable even
    # if a damaged attachment boundary makes BODYSTRUCTURE unavailable.
    folder = 'broken-multipart'
    assert s.rpc('storage', op='folder_create', username=user, folder=folder)['ok']
    assert s.rpc('storage', op='append', username=user, folder=folder,
                 raw=prefix + b'Subject: still visible\r\nContent-Type: multipart/mixed; boundary=missing\r\n\r\ntruncated body')['ok']
    with closing(Wire(s)) as wire:
        wire.login(user)
        wire.command('select', 'SELECT "' + folder + '"')
        _, metadata = fetch_values(wire, '(ENVELOPE)')
        assert metadata[b'ENVELOPE'].data[1].data == b'still visible'
    print('PASS strict IMAP multipart grammar, UTF-8 metadata literals, RFC 5322 addresses, opaque transfer encodings, large forwarded messages and partial MIME sections', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, required=True)
    args = parser.parse_args()
    directory = ROOT / 'build/test-runs' / ('imap-mime-' + secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite = Suite(args.bin_dir.resolve(), directory)
    try:
        run(suite)
    finally:
        suite.close()
