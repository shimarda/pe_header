# PEファイルのヘッダ情報を出力するツール(まだ不具合あり)
### 大学の授業の実験で作成したobjdump, dumpbinの縮小版のようなもの
各フィールドのヘッダ情報を出力

ファイルから得たヘッダ情報を以下のサイトのテーブルと照らし合わせて特性を出力

https://learn.microsoft.com/ja-jp/windows/win32/debug/pe-format

上手く動かない部分

・テーブルと値が一致しても特性などが出力出来ない場合がある。

・テーブルに無いフラグが定義されているため、特性が分からない。

開発予定は無し。
