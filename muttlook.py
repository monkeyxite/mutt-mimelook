#!/usr/bin/env python3

import os
import sys
import re
import base64
import subprocess
import html

import mailparser  # mail-parser
import markdown  # Markdown
import magic  # python-magic (for mimetypes)
from mailparser_reply import EmailReplyParser

# due to some reason could not source mutt.cmd
commandsFile = "/tmp/muttlook/mutt_cmd"
markdownFile = "/tmp/muttlook/mimelook-md"
# orgMsg is generated everything when starting drafting reply via mutt-trim, configed via $editor in mutt
orgMsg = "/tmp/muttlook/original.msg"
htmlFile = "/tmp/muttlook/mimelook.html"
logFile = "/tmp/muttlook/mimelog.log"
# TODO: add Swedish and Chinese later
languages = ['en', 'de']

import logging
import logging.handlers
import os

import shortuuid
 
# Configure the logging system
logging.basicConfig(
    level=logging.INFO,  # Set the desired log level (INFO, WARNING, ERROR, etc.)
    format='%(asctime)s - %(levelname)s - %(message)s',  # Define the log message format
    datefmt='%Y-%m-%d %H:%M:%S',
    filename=logFile,  # Specify the log file path
    filemode='w'  # 'w' for write mode, 'a' for append mode (optional, default is 'a')
# Define the timestamp format
)
 
QUOTE_ESCAPE = "MIMELOOK_QUOTES"
mime = magic.Magic(mime=True)



def export_inline_attachments(message, dstdir):
    # find inline attachments in plaintext version
    #inlines = re.findall("\[cid:.*?\]", message.body.split("--- mail_boundary ---")[0])
    # TODO: better match test like html detect part
    try:
        message_html = message.body.split("--- mail_boundary ---")[1]
    except IndexError as e:
        logging.error("org message does not have mail_boundary: {} :( )\n".format(e))
        message_html = message.body
    else:
        logging.error("org message has mail_boundary :) \n")
    # .. or html version (probably safer?):
    inlines = re.findall("src=\"cid:.*?\"", message_html)

    # return list of tuples: (attachment id, exported file)
    ret = []

    for inline in inlines:
        # find filename
        name_match = re.search("cid:.*@", inline)

        # find content id
        id_match = re.search("@.*", inline)
        attachment_id = inline[id_match.start()+1:-1]
        # TODO: clear the unbound
        # if id_match := re.search("@.*", inline):
        #     attachment_id = inline[id_match.start()+1:-1]
        # else:
        #     attachment_id = None

        # find corresponding attachment in the message
        attachment_name = inline[name_match.start()+4:name_match.end()-1]
        attachment = [x for x in message.attachments if x["content-id"].startswith("<{}".format(attachment_name))]
        assert len(attachment) == 1, "Could not get attachment '{}'".format(attachment_name)
        attachment = attachment[0]

        # base64 decode the file and place it in dstdir
        assert attachment["content_transfer_encoding"] == "base64", "Only base64 currently supported"
        b = base64.decodebytes(bytes(attachment["payload"], "ascii"))
        dstfile = os.path.join(dstdir, attachment_name)
        with open(dstfile, "wb") as f:
            f.write(b)

        # same attachment might occur multiple times - only add it once
        att = (attachment_id, dstfile)
        if att not in ret:
            ret.append(att)

    return ret

# make "from: x, sent: d/m-y, to: z, ..." section in outlook style
# grabbed from what outlook webmail does
def format_insane_outlook_header(fromaddr, sent, to, cc, subject):
    ret = """<hr style="display:inline-block;width:98%" tabindex="-1">
<div id="divRplyFwdMsg" dir="ltr"><font face="Calibri, sans-serif" style="font-size:11pt" color="#000000"><b>From:</b> {}<br>
<b>Sent:</b> {}<br>
""".format(fromaddr, sent)

    if to is not None:
        ret += "<b>To:</b> {}<br>\n".format(to)

    if cc is not None:
        ret += "<b>Cc:</b> {}<br>\n".format(cc)

    ret += """<b>Subject:</b> {}</font>
<div>&nbsp;</div>
</div>
""".format(subject)

    return ret


# get message_from_pipemsg
def message_from_pipe(pipe):
    message = mailparser.parse_from_string(pipe)
    return message

# get message from id
def message_from_msgid(msgid):
    # mucmd = "mu find msgid:{} --fields 'l'".format(msgid)
    # using notmuch
    nm_cmd = "notmuch search --output=files id:{}".format(msgid)
    p = subprocess.Popen(nm_cmd.split(" "), stdout=subprocess.PIPE)
    messagefiles, _ = p.communicate()
    messagefiles = messagefiles.decode("utf-8").split("\n")

    # check return code ok
    assert p.returncode == 0, "notmuch find failed"

    # expecting list of at least 1 message and one empty line
    assert(len(messagefiles) > 1), "notmuch found no messages"

    # use first hit and strip surrounding '
    messagefile = messagefiles[0]

    # parse message and grab HTML
    message = mailparser.parse_from_file(messagefile)

    return message

# create crazy outlook-style html reply from message id and the desired html message
def format_outlook_reply(message, htmltoinsert):
    # Restruct find html part via mail boundary
    pattern = r"--- mail_boundary ---"
    substrings = re.split(pattern, message.body, flags=re.IGNORECASE)
    if len(substrings) == 1:
        logging.info("org message does not have mail_boundary! ")
        message_html = message.body
    for _, substring in enumerate(substrings[1:], 1):  # Skip the first element (before the first match)
        m = re.search("<body.*?>", substring)
        if m is not None:
            message_html = substring.strip()
            break
    else:
        message_html = substrings[-1].strip()
    # convert CRLF to LF
    message_html = message_html.replace("\r\n", "\n")

    # grab header info
    message_from = message.headers["From"]
    message_to = message.headers["To"] if "To" in message.headers else None
    message_subject = message.headers["Subject"]
    message_date = message.date.strftime("%d %B %Y %H:%M:%S")
    message_cc = message.headers["CC"] if "CC" in message.headers else None

    outlook_madness = format_insane_outlook_header(message_from, message_date,
                                                   message_to, message_cc, message_subject)

    # find body tag in html
    m = re.search("<body.*?>", message_html)
    assert m is not None, "No body tag found in parent HTML"

    # format resulting html email:
    # ..<body> from email being replied to
    # reply message
    # "from yada yada" section
    # remainder of email being replied to
    html = "{}\n{}\n{}\n{}".format(message_html[:m.end()],
                                   htmltoinsert,
                                   outlook_madness,
                                   message_html[m.end():])

    return html


# Convert "> "-style quotes into something else that passes untouched through html.escape()
# Escaped quotes look like this: [[MIMELOOK_QUOTES|X]] where X denotes the
# number of quotes that have been escaped
def escape_quotes(plaintext):
    ret = ""
    for line in plaintext.split("\n"):
        if line.startswith(">"):
            i = 0
            while i < len(line) and line[i] == ">":
                i += 1
            ret += "[[{}|{}]]".format(QUOTE_ESCAPE, i)
            ret += line[i:] + "\n"
        else:
            ret += line + "\n"

    return ret


# Convert previously escaped "> "-style quotes back to their original form.
def unescape_quotes(string):
    retstr = ""
    i = 0

    while i < len(string):
        # find start position of next escaped quote group
        p = string[i:].find("[[{}|".format(QUOTE_ESCAPE))

        if p < 0:
            # no more escaped quotes - grab the rest of the string and return
            retstr += string[i:]
            break

        # found some escaped quotes, grab content of string upto them
        retstr += string[i:i+p]

        # find end of the escaped quote tag
        tag_end_pos = string[i+p:].find("]]")

        # grab the number from the tag
        nquotes = int(string[i+p+2+len(QUOTE_ESCAPE)+1:i+p+tag_end_pos])

        # append that number of quotes
        retstr += ">"*nquotes

        # advance to the character just after the tag
        i += p+tag_end_pos+2

    return retstr


def escape_signature_linebreaks(plaintext):
    m = re.search("^-- ", plaintext, re.MULTILINE)
    if m is not None:
        content = plaintext[:m.start()]
        signature = plaintext[m.start():]
        signature = signature.replace("\n", "  \n")
        return content + signature
    else:
        return plaintext


# Find MIME parts in the plaintext
# Returns plaintext without parts and list of parts
# Warning: assumes only valid <#part...><#/part> tags after the first occurence
# of "<#part" !
def find_mime_parts(plaintext):
    parts = re.findall("<#part.*?<#/part>", plaintext, re.DOTALL)
    m = re.search("<#part.*?<#/part>", plaintext, re.DOTALL)
    if m is not None:
        text = plaintext[:m.start()]
    else:
        text = plaintext
    return text, parts


# Escape HTML. Don't escape lines that start with four spaces, since
# these will be wrapped by <pre> tags by the Markdown-to-html
# conversion.
def html_escape(text):
    ret = ""
    for line in text.split("\n"):
        if not line.startswith("    "):
            ret += html.escape(line) + "\n"
        else:
            ret += line + "\n"

    return ret


# Take desired plaintext message and id of message being replied to
# and format a multipart message with sane plaintext section and
# insane outlook-style html section. The plaintext message is converted
# to HTML supporting markdown syntax.
def plain2fancy(msg):
    # INFO: Parser drafted reply via stdin msg
    reply = EmailReplyParser(languages=languages).read(text=msg) 
    latest_reply = reply.latest_reply
    if latest_reply is not None:
        # plaintext is converted to html, supporting markdown syntax
        # loosely inspired by http://webcache.googleusercontent.com/search?q=cache:R1RQkhWqwEgJ:tess.oconnor.cx/2008/01/html-email-composition-in-emacs
        text2html = markdown.markdown(latest_reply)
    else:
        latest_reply = ''
        text2html = ""
    
    # Q&D way to get msg_id of the orignal msg to reply,  refer orgMsg def 
    org_reply_msg = mailparser.parse_from_file(orgMsg)

    reply_to_id = org_reply_msg.headers['In-Reply-To'][1:-1]
    # logging.info("Reply-To-ID: {}\n".format(reply_to_id))
    message = message_from_msgid(reply_to_id)
    # logging.info("original message:\n{}\n".format(message.body))

    # insane outlook-style html reply
    madness = format_outlook_reply(message, text2html)
    # logging.info("formated message:\n{}\n".format(madness))

    # find inline attachments and export them to a temporary dir
    uuid = shortuuid.uuid(name=reply_to_id)
    attdir = "/tmp/muttlook/{}".format(uuid)
    if not os.path.isdir(attdir):
        os.mkdir(attdir)
    # attachments from mail to be replied
    attachments = export_inline_attachments(message, attdir)
    # logging.info("Old attachments:\n{}\n".format(str(attachments)))

    # Find inline attachment in reply and change md 
    # re: !\[([^]]*)\]\(([^)]+)\)
    # logging.info("reply text after htmlize is: {}\n".format(text2html))
    link_pattern = r'!\[.*?\]\((.*?)\)'
    matches = re.findall(link_pattern, latest_reply)
    # Replace in-line links with CID attachments and modify original links
    if matches:
        cid_mapping = {}
        new_reply = latest_reply
        for link in matches:
            id = link.split("/")[-1]  # Extract the file name as CID
            cid = shortuuid.uuid(name=id)
            cid_mapping[cid] = link
            for new_cid_link, original_link  in cid_mapping.items():
                new_reply = latest_reply.replace(original_link, f"cid:{new_cid_link}")
        if new_reply != latest_reply:
            new_msg = msg.replace(latest_reply, new_reply)
            new_html = madness.replace(original_link, f"cid:{new_cid_link}")
        attachments.extend(list(cid_mapping.items()))
    else:
        new_msg = msg
        new_html = madness
    logging.info("Final attachments:\n{}\n".format(str(attachments)))

    # build string of <#part type=x filename=y disposition=inline><#/part> for each
    # attachment, separated by newlines
    attachment_str = ""
    for attachment in attachments:
        attachment_str += "<attach-file>'{}'<enter><toggle-disposition><edit-content-id>^u'{}'<enter><tag-entry>"\
            .format(attachment[1], attachment[0])
    # write html message to file for inspection before sending
    with open(htmlFile, "w") as f:
        f.write(new_html)

    with open(markdownFile, "w") as f:
        f.write(new_msg)

    if attachment_str:
        mutt_cmd = "push <attach-file>'{}'<enter><toggle-disposition><toggle-unlink><first-entry><detach-file><attach-file>'{}'<enter><toggle-disposition><toggle-unlink><tag-entry><previous-entry><tag-entry><group-alternatives>{}<first-entry><tag-entry><group-related>".format(markdownFile, htmlFile, attachment_str)
    else:
        mutt_cmd = "push <attach-file>'{}'<enter><toggle-disposition><toggle-unlink><tag-entry><previous-entry><tag-entry><group-alternatives>".format( htmlFile)
    with open(commandsFile, "w") as f:
        f.write(mutt_cmd)
    # return madness

if __name__ == '__main__':
    # stdin from pipe-message is full drafted msg
    stdin = sys.stdin.read()
    msg = stdin

    # TODO: dummy plaintext for new TODO update later
    # logging.info("piped entry is :\n{}\n".format(msg))

    try:
        plain2fancy(msg)
    except Exception as e:
        # logging.info("final message:\n{}\n".format(e))
        raise e
