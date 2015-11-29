# Makefile for Lesamnta-LW reference C99 implementation
# Note: Lesamnta is a registered trademark of Hitachi, Ltd. in Japan.
#
#
# Released under the MIT license
# Copyright (C) 2015 Hidenori Kuwakado
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
#(the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

CC=gcc
CFLAGS=-std=c99 -pedantic -I. -O2

lesamnta-LW: main.o lesamnta-LW.o
	$(CC) main.o lesamnta-LW.o -o $@
main.o: main.c lesamnta-LW.h
	$(CC) main.c -o $@ -c $(CFLAGS)
lesamnta-LW.o: lesamnta-LW.c lesamnta-LW.h
	$(CC) lesamnta-LW.c -o $@ -c $(CFLAGS)

.PHONY: clean
clean:
	rm -f *.o lesamnta-LW

.PHONY: test
test: lesamnta-LW
	./lesamnta-LW --testVector
	./lesamnta-LW message1.txt
	./lesamnta-LW message2.txt
	./lesamnta-LW message3.txt

# end of file
