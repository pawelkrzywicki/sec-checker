#!/usr/bin/env python3
"""Configure the shared app password locally, without printing secrets."""
import argparse
import getpass
from pathlib import Path
import secrets
from werkzeug.security import generate_password_hash

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--generate',action='store_true',help='Generate a password and save it to .initial-password')
    args=parser.parse_args()
    root=Path(__file__).resolve().parent
    env=root/'.env'
    text=env.read_text() if env.exists() else ''
    if args.generate and any(line.startswith(('SEC_CHECKER_PASSWORD=','SEC_CHECKER_PASSWORD_HASH=')) and line.split('=',1)[1].strip().strip("'\"") for line in text.splitlines()):
        print('An app password is already configured; existing settings were preserved.')
        return
    password=secrets.token_urlsafe(24) if args.generate else getpass.getpass('New Sec Checker password (12+ characters): ')
    if len(password)<12:raise SystemExit('Use at least 12 characters.')
    if not args.generate and password!=getpass.getpass('Confirm password: '):raise SystemExit('Passwords did not match; nothing changed.')
    lines=[line for line in text.splitlines() if not line.startswith(('SEC_CHECKER_PASSWORD=','SEC_CHECKER_PASSWORD_HASH='))]
    lines.append("SEC_CHECKER_PASSWORD_HASH='"+generate_password_hash(password)+"'")
    # Both files are private and ignored by Git. Never echo the password/hash.
    with open(env,'w',opener=lambda path,flags:__import__('os').open(path,flags,0o600)) as stream:stream.write('\n'.join(lines)+'\n')
    env.chmod(0o600)
    initial=root/'.initial-password'
    if args.generate:
        with open(initial,'w',opener=lambda path,flags:__import__('os').open(path,flags,0o600)) as stream:stream.write(password+'\n')
        initial.chmod(0o600)
        print('Generated password saved to '+str(initial))
    elif initial.exists():initial.unlink()
    print('Password hash configured in .env. Recreate the container to apply it.')

if __name__=='__main__':main()
