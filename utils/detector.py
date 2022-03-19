import os
import sys
from getpass import getuser

import cv2

user = getuser()

ROOT = fr'\Users\{user}\Pictures\Wallpapers'
FACES = f'{ROOT}/faces'
TRAIN = '../resources'

if not os.path.isdir(ROOT):
    print('Root folder not found')
    sys.exit(1)

if not os.path.isdir(FACES):
    os.mkdir(FACES)


def detect(src_dir=ROOT, tgt_dir=FACES, train_dir=TRAIN):
    for fname in os.listdir(src_dir):
        if not fname.upper().endswith('.JPG') and not fname.upper().endswith('.PNG'):
            continue
        full_name = os.path.join(src_dir, fname)
        new_name = os.path.join(tgt_dir, fname)
        img = cv2.imread(full_name)
        if img is None:
            continue

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        training = os.path.join(train_dir, 'haarcascade_frontalface_alt.xml')
        cascade = cv2.CascadeClassifier(training)
        rects = cascade.detectMultiScale(gray, 1.3, 5)
        try:
            if rects.any():
                print('Detected a face')
                rects[:, 2:] += rects[:, :2]
        except AttributeError:
            print(f'No faces found in {fname}.')
            continue

        # evidenzia i volti nell'immagine
        for x1, y1, x2, y2 in rects:
            cv2.rectangle(img, (x1, y1), (x2, y2), (127, 255, 0), 2)
        cv2.imwrite(new_name, img)


if __name__ == '__main__':
    detect()
