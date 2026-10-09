"""Render the pinned existing launcher with one Auth coordinator target.

Rendering allocates nothing. Invoking the result requires separate authority.
"""
import argparse
from pathlib import Path
import shared_backend

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--backend',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    captured = shared_backend.capture(args.backend)
    owner = Path(__file__).with_name('auth_owner.py').absolute()
    policy = owner.parent.parent/'customer-refresh-native-create-policy-v1-20261009/create_policy.py'
    import auth_proof
    auth_proof.policy_module(policy)
    source = shared_backend.launcher_source(captured['Start-FinancialIamHostedOwner.ps1'],args.backend,owner)
    with args.output.open('x',encoding='utf-8',newline='\n') as stream:
        stream.write(source)

if __name__ == '__main__': main()
