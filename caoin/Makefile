# caoin 构建 / 安装 / 发布
#
# 常用：
#   make            构建用户态工具与测试目标（需要 aarch64 交叉编译器）
#   make install    安装到 $(PREFIX)（默认 /usr/local）
#   make dist       生成源码发布包 dist/caoin-<version>.tar.gz
#   make dist-bin   生成带二进制的发布包（需先 make）

VERSION  := $(shell cat VERSION 2>/dev/null || echo 0.1.0)
PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin
SHAREDIR ?= $(PREFIX)/share/caoin
DESTDIR  ?=
CC       ?= aarch64-linux-gnu-gcc

DISTNAME := caoin-$(VERSION)
DISTDIR  := dist/$(DISTNAME)

.PHONY: all cli user tests install uninstall dist dist-src dist-bin clean help

all: cli user

# 统一 CLI 是纯 shell，不依赖交叉编译器
cli:
	@mkdir -p build
	install -m 755 cli/caoin build/caoin

user:
	CC="$(CC)" bash build.sh

tests: user

install: all
	install -d "$(DESTDIR)$(BINDIR)" "$(DESTDIR)$(SHAREDIR)/kpm" "$(DESTDIR)$(SHAREDIR)/docs"
	install -m 755 build/caoin build/caoin_prep "$(DESTDIR)$(BINDIR)/"
	install -m 644 README.md LICENSE VERSION "$(DESTDIR)$(SHAREDIR)/"
	cp -R caoin_ko/. "$(DESTDIR)$(SHAREDIR)/kpm/"
	install -m 644 docs/*.md "$(DESTDIR)$(SHAREDIR)/docs/"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/caoin" "$(DESTDIR)$(BINDIR)/caoin_prep"
	rm -rf "$(DESTDIR)$(SHAREDIR)"

# 源码发布包：不含交叉编译产物，目标机器上 make 即可
dist: dist-src

dist-src:
	rm -rf "$(DISTDIR)"
	install -d "$(DISTDIR)"
	cp -R cli caoin_ko hook tests docs "$(DISTDIR)/"
	cp README.md LICENSE VERSION build.sh Makefile "$(DISTDIR)/"
	tar -czf "dist/$(DISTNAME).tar.gz" -C dist "$(DISTNAME)"
	@echo "dist/$(DISTNAME).tar.gz"

# 二进制发布包：CLI + caoin_prep + KPM 源码与文档
dist-bin: all
	rm -rf "$(DISTDIR)"
	install -d "$(DISTDIR)/bin" "$(DISTDIR)/share/caoin/kpm" "$(DISTDIR)/share/caoin/docs"
	install -m 755 build/caoin build/caoin_prep "$(DISTDIR)/bin/"
	install -m 644 README.md LICENSE VERSION "$(DISTDIR)/share/caoin/"
	cp -R caoin_ko/. "$(DISTDIR)/share/caoin/kpm/"
	install -m 644 docs/*.md "$(DISTDIR)/share/caoin/docs/"
	install -m 755 build.sh "$(DISTDIR)/"
	install -m 644 Makefile "$(DISTDIR)/"
	tar -czf "dist/$(DISTNAME)-bin.tar.gz" -C dist "$(DISTNAME)"
	@echo "dist/$(DISTNAME)-bin.tar.gz"

clean:
	rm -rf build dist hook/build

help:
	@echo "make            构建用户态工具与测试目标"
	@echo "make cli        只安装统一 CLI 到 build/caoin"
	@echo "make install    安装到 PREFIX=$(PREFIX)"
	@echo "make dist       源码发布包"
	@echo "make dist-bin   带二进制的发布包（需先 make）"
	@echo "make clean      清理构建产物"
