# sev-snp-measure

Sign VME-SNP binaries using `fortanixvme-snp-sign`

## Running

1. Environment Setup
    - Setup a virtual environment
        - `python3 -m venv env`
    - Activate the environment
        - `source env/bin/activate`
    - Install the packages needed
        - `pip3 install -r requirements.txt`
2. Set the following two environment variables
    - `FORTANIX_API_ENDPOINT`: set this to point at the DSM endpoint
    - `FORTANIX_API_KEY`: set this as the access to the app which will generate the signature
3. Example invocation:
    - `./fortanixvme-snp-sign --ovmf OVMF.amdsev.fd --kernel vmlinuz-6.18.0-8-generic.unsigned.efi --guest-svn 0 --family-id 00000000000000000000000000000000 --image-id 00000000000000000000000000000000 --id-key-dsm-id 84158813-4688-4e92-90db-9509bc141ec2 --out-prefix sig`

## Development

Run all unit tests:

    pip install -r requirements.txt
    make test

Check unit tests coverage:

    pip install coverage
    make coverage
    # See HTML coverage report in htmlcov/

Check Python type hints:

    pip install mypy
    make typecheck

Check Python coding style:

    pip install flake8
    make lint

## Notes

If you have any questions or issues you can create a new [issue
here](https://github.com/fortanix/sev-snp-measure/issues/new)

Pull requests are welcome!

## License

Apache 2.0 license.
