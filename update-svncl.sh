#!/bin/sh

svn2cl -i --break-before-msg --reparagraph -r HEAD:1 $*
