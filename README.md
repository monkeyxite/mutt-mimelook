# Muttlook

## Background

Fork from a tool for [mu4e-mimelook](https://github.com/tausen/mu4e-mimelook), creating a mutt assistance tool to reply HTML mail (mainly outlook) without reconstruct the original format, with markdown replies.

- Support reply with Markdown but maintain the style
- Support inline image

### Other dependencies

There are many tools installed in the machine to run the script for the purpose.

- Neomutt (edit-content-id and MIME alternative multipart support) not upstream mutt.
- Create tmp folder /tmp/muttlook?
- [Mutt-trim](https://github.com/Konfekt/mutt-trim/blob/master/mutt-trim)

### Python dependencies

- mail-parser (<https://pypi.org/project/mail-parser/>, tested with v3.9.3)
- mail-parser-reply (https://github.com/alfonsrv/mail-parser-reply), tested with v3.11
- Markdown (<https://Python-Markdown.github.io/>, tested with v3.1.1)
- python-magic (<http://github.com/ahupp/python-magic>, tested with v0.4.15)
- libmagic (e.g., libmagic1 on Ubuntu or libmagic in homebrew)

Tested with Python 3.11.

## Usage

1. Modify muttrc 
2. Modify mutt-trim

## To-do

- [x] Clean LSP diagnostics (unbound/…)
- [ ] regex to filler out already cid or remote links
- [ ] refectory and better documentation
- [ ] clean madness after send: copy markdown attachment into tmp folder to enable so.
- [ ] Test case for other occasions:
    - Gmail HTML
    - Gmail plain text
    - Outlook HTML  
    - Outlook plain text.

## Credits

- [mu4e-mimelook](https://github.com/tausen/mu4e-mimelook)
- [convert-multipart](https://git.jonathanh.co.uk/jab2870/Dotfiles/src/commit/08af357f4445e40e98c715faab6bb3b075ec8afa/bin/.bin/emails/convert-multipart)
- [MIMEmbellish](https://gist.github.com/oblitum/6eeffaebd9a4744e762e49e6eb19d189#file-mimembellish)
