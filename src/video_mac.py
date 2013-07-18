import os
import sys
from Crypto.Hash import SHA256

if __name__ == '__main__':
    if len(sys.argv) == 1:
        print 'Expected file path as an argument'
    else:
        FILENAME = sys.argv[1]

        BLOCK_SIZE = 1024

        block_list = []

        # Read the given file a block at a time
        with open(FILENAME, 'rb') as video_file:
            while True:
                data = video_file.read(BLOCK_SIZE)
                if data:
                    block_list.append(data)
                else:
                    break

        # Assert that the file has been read in the correct manner
        assert sum([len(block) for block in block_list]) == os.path.getsize(FILENAME)

        # Perform the MAC check on each block read from the file
        prev_hash = None
        for block in reversed(block_list):
            h = SHA256.new()

            if prev_hash is None:
                h.update(block)
            else:
                h.update(block + prev_hash.hexdigest().decode('hex'))

            prev_hash = h

        # Assert that an operation was performed
        assert prev_hash is not None

        # Print out our result
        print 'h0 is %s' % prev_hash.hexdigest()
