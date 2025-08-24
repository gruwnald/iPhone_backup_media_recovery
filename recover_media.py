#!/usr/bin/env python

import sys
import os
import hashlib
import shutil
from datetime import datetime as dt
import click

mbdx = {}

def getint(data, offset, intsize):
    """Retrieve an integer (big-endian) and new offset from the current offset"""
    value = 0
    while intsize > 0:
        value = (value << 8) + data[offset]  # Python 3: data[offset] is already int
        offset += 1
        intsize -= 1
    return value, offset

def getstring(data, offset):
    """Retrieve a string (as bytes) and new offset into the data"""
    if data[offset] == 0xFF and data[offset+1] == 0xFF:
        return b'', offset + 2  # Blank string
    length, offset = getint(data, offset, 2)  # 2-byte length
    value = data[offset:offset+length]
    return value, offset + length

def process_mbdb_file(filename):
    mbdb = {}  # Map offset => file info
    with open(filename, 'rb') as f:
        data = f.read()
    if data[0:4] != b"mbdb":
        raise Exception("This does not look like an MBDB file")
    offset = 4
    offset += 2  # skip unknown bytes (usually 0x05 0x00)

    while offset < len(data):
        fileinfo = {}
        fileinfo['start_offset'] = offset
        fileinfo['domain'], offset = getstring(data, offset)
        fileinfo['filename'], offset = getstring(data, offset)
        fileinfo['linktarget'], offset = getstring(data, offset)
        fileinfo['datahash'], offset = getstring(data, offset)
        fileinfo['unknown1'], offset = getstring(data, offset)
        fileinfo['mode'], offset = getint(data, offset, 2)
        fileinfo['unknown2'], offset = getint(data, offset, 4)
        fileinfo['unknown3'], offset = getint(data, offset, 4)
        fileinfo['userid'], offset = getint(data, offset, 4)
        fileinfo['groupid'], offset = getint(data, offset, 4)
        fileinfo['mtime'], offset = getint(data, offset, 4)
        fileinfo['atime'], offset = getint(data, offset, 4)
        fileinfo['ctime'], offset = getint(data, offset, 4)
        fileinfo['filelen'], offset = getint(data, offset, 8)
        fileinfo['flag'], offset = getint(data, offset, 1)
        fileinfo['numprops'], offset = getint(data, offset, 1)
        fileinfo['properties'] = {}
        for _ in range(fileinfo['numprops']):
            propname, offset = getstring(data, offset)
            propval, offset = getstring(data, offset)
            # decode as utf-8 safely, replace invalid bytes
            propname_str = propname.decode("utf-8", "replace")
            propval_str = propval.decode("utf-8", "replace")
            fileinfo['properties'][propname_str] = propval_str

        mbdb[fileinfo['start_offset']] = fileinfo
        fullpath = (fileinfo['domain'] + b'-' + fileinfo['filename']).decode("utf-8", "replace")
        id = hashlib.sha1(fullpath.encode('utf-8'))
        mbdx[fileinfo['start_offset']] = id.hexdigest()
    return mbdb

def modestr(val):
    def mode(val):
        r = 'r' if (val & 0x4) else '-'
        w = 'w' if (val & 0x2) else '-'
        x = 'x' if (val & 0x1) else '-'
        return r + w + x
    return mode(val >> 6) + mode((val >> 3)) + mode(val)

def fileinfo_str(f, verbose=False):
    if not verbose:
        return "(%s)%s::%s" % (f.get('fileID','<nofileID>'),
                               f['domain'].decode("utf-8", "replace"),
                               f['filename'].decode("utf-8", "replace"))
    mode_type = (f['mode'] & 0xE000)
    if mode_type == 0xA000: ftype = 'l'  # symlink
    elif mode_type == 0x8000: ftype = '-'  # file
    elif mode_type == 0x4000: ftype = 'd'  # dir
    else: ftype = '?'  # unknown
    info = ("%s%s %08x %08x %7d %10d %10d %10d (%s)%s::%s" %
            (ftype, modestr(f['mode'] & 0x0FFF),
             f['userid'], f['groupid'], f['filelen'],
             f['mtime'], f['atime'], f['ctime'],
             f.get('fileID','<nofileID>'),
             f['domain'].decode("utf-8", "replace"),
             f['filename'].decode("utf-8", "replace")))
    if ftype == 'l':
        info += ' -> ' + f['linktarget'].decode("utf-8", "replace")
    for name, value in f['properties'].items():
        info += ' ' + name + '=' + repr(value)
    return info


def extension(s):
    if isinstance(s, bytes):
        s = s.decode("utf-8", "replace")
    return s[s.rfind('.'):].lower()


def create_folder_in_not_exists(name):
    if not os.path.exists(name):
        os.makedirs(name)


@click.command()
@click.argument("backup_path", type=click.Path(exists=True, file_okay=False))
def main(backup_path):
    mbdb_path = os.path.join(backup_path, 'Manifest.mbdb')
    mbdb = process_mbdb_file(mbdb_path)
    media_extensions = ['.jpg', '.jpeg', '.png', '.tiff', '.heic', '.mov', '.mp4', '.mp3', '.pdf']
    media_recovered = 0
    seen_dates = {}

    dest_folder = os.path.join('recovered_media', os.path.basename(backup_path))
    create_folder_in_not_exists(dest_folder)

    for offset, fileinfo in mbdb.items():
        if offset in mbdx:
            fileinfo['fileID'] = mbdx[offset]
            src_path = os.path.join(backup_path, fileinfo["fileID"])
            ext = extension(fileinfo['filename'])
            if ext in media_extensions:
                date = dt.fromtimestamp(fileinfo['ctime']).strftime("%Y_%m_%d")
                if date in seen_dates:
                    seen_dates[date] += 1
                else:
                    seen_dates[date] = 1
                dest_path = os.path.join(dest_folder, f"{date}_{seen_dates[date]}{ext}")
                
                try:
                    shutil.copy(src_path, dest_path)
                    media_recovered += 1
                except FileNotFoundError:
                    print(f"Could not locate file {fileinfo["fileID"]} ({fileinfo["filename"].decode("utf-8")})")
            
        else:
            fileinfo['fileID'] = "<nofileID>"
            print("No fileID found for", fileinfo_str(fileinfo, verbose=True), file=sys.stderr)
    print(f"Recovered {media_recovered} media files!")


if __name__ == "__main__":
    main()