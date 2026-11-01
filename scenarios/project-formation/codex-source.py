#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 tao3k team and Contributors
#
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Bounded read-only Codex app-server transport. No inference or authority issuance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import time


def observe(thread, turn, messages):
    cli = shutil.which('codex')
    if not cli:
        raise RuntimeError('configured Codex executable is unavailable')
    cli = Path(cli).resolve(strict=True)
    fingerprint = hashlib.sha256(cli.read_bytes()).hexdigest()
    deadline = time.monotonic() + 25
    process = subprocess.Popen([str(cli), 'app-server', '--stdio', '-c', 'analytics.enabled=false'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    buffer = b''
    consumed = 0
    request_id = 0

    def rpc(method, params):
        nonlocal buffer, consumed, request_id
        request_id += 1
        process.stdin.write((json.dumps(dict(id=request_id, method=method, params=params))+'\n').encode())
        process.stdin.flush()
        while time.monotonic() < deadline:
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                if not line:
                    continue
                response = json.loads(line)
                if response.get('id') == request_id:
                    if 'error' in response:
                        # Never include an arbitrary remote diagnostic or token in output.
                        raise RuntimeError('Codex read RPC refused: '+method)
                    return response['result']
            remaining = deadline-time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                break
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                raise RuntimeError('Codex read transport closed')
            consumed += len(chunk)
            if consumed > 16777216:
                raise RuntimeError('Codex response byte bound exceeded')
            buffer += chunk
        raise RuntimeError('Codex read deadline exceeded')

    def account():
        result = rpc('account/read', {'refreshToken': False})
        value = result.get('account')
        # Transport redaction only. Scheme owns evidence and authority semantics.
        return {'type': value.get('type'),
                'emailSha256': hashlib.sha256(value['email'].encode()).hexdigest()
                    if isinstance(value.get('email'), str) and value['email'] else None
               } if isinstance(value, dict) else None

    try:
        rpc('initialize', {'clientInfo': {'name': 'deterministic_engineering_source',
            'version': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}})
        process.stdin.write(b'{"method":"initialized"}\n')
        process.stdin.flush()
        before = account()
        metadata = rpc('thread/read', {'threadId': thread, 'includeTurns': False})['thread']
        selected = {}
        cursor = None
        for _ in range(8):
            params = dict(threadId=thread, turnId=turn, limit=32, sortDirection='asc')
            if cursor is not None:
                params['cursor'] = cursor
            page = rpc('thread/items/list', params)
            for entry in page['data']:
                item = entry['item']
                if item.get('id') in messages:
                    selected[item['id']] = {'turnId': entry['turnId'], 'item': item}
            if all(identity in selected for identity in messages):
                break
            cursor = page.get('nextCursor')
            if cursor is None:
                break
        latest_user = None
        cursor = None
        for _ in range(8):
            params = dict(threadId=thread, limit=32, sortDirection='desc')
            if cursor is not None:
                params['cursor'] = cursor
            page = rpc('thread/items/list', params)
            latest_user = next((dict(turnId=row['turnId'], messageId=row['item']['id'])
                for row in page['data'] if row['item'].get('type') == 'userMessage'), None)
            if latest_user is not None:
                break
            cursor = page.get('nextCursor')
            if cursor is None:
                break
        after = account()
        if hashlib.sha256(cli.read_bytes()).hexdigest() != fingerprint:
            raise RuntimeError('Codex executable changed during observation')
        return {'accountBefore': before, 'accountAfter': after,
                'threadId': metadata['id'], 'cwd': metadata['cwd'],
                'messages': [selected[x] for x in messages if x in selected],
                'latestUser': latest_user,
                'executable': str(cli), 'executableSha256': fingerprint}
    finally:
        selector.close()
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stdin.close()
        process.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--thread', required=True)
    parser.add_argument('--turn', required=True)
    parser.add_argument('--message', action='append', required=True)
    args = parser.parse_args()
    if not (1 <= len(args.message) <= 16) or len(set(args.message)) != len(args.message):
        parser.error('one to sixteen distinct message references required')
    for value in [args.thread, args.turn, *args.message]:
        if not value or len(value) > 256:
            parser.error('bounded nonempty source references required')
    print(json.dumps(observe(args.thread, args.turn, args.message), ensure_ascii=False))


if __name__ == '__main__':
    main()
