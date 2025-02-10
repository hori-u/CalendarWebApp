# カレンダーWebアプリケーション

複数ユーザがスケジュールを共有することができるカレンダーアプリ

# デモ



https://github.com/user-attachments/assets/b37bb173-d20c-4a08-96d5-4a7f87db498d



# 特徴

異なる機能でもプログラム的に同じ動作であれば同じ関数を使用している．例えばカレンダーにスケジュールを追加する機能と編集する機能は同じ関数を使用している．

# 動作環境

* go version go1.22.5 windows/amd64
* SQLite version 3.47.2 2024-12-07 20:39:59

# インストール

* git clone 
```
git clone https://github.com/hori-u/FPSGameProject.git
```
* 初期化
 * Windows：
   ```
   delete_database.bat
   ```
 * Linux：
   ```
   ./delete_database.sh
   ```

# 使用方法

* ターミナルで実行
```
go run main.go
```
ブラウザで http://localhost:8080/ に接続

* 機能
  * Adminユーザが存在しなければAdminユーザを追加
  * Adminユーザのログイン
  * Adminユーザによる通常ユーザの追加
  * 通常ユーザのログイン
  * カレンダーの表示
  * カレンダーにスケジュールを追加
  * カレンダーのスケジュールを編集
  * カレンダーのスケジュールを削除

# ノート

今後の実装として，カレンダーのUIの改善や年ごとのカレンダー表示機能を追加したい．

# 使用言語

* フロントエンド：
  HTML，JavaScript
* バックエンド：
  Go

# 作者

* 作成者 : 堀 悠人（Hori Yuto）
* 所属 : 岡山大学大学院環境生命自然科学研究科（Graduate School of Environment, Life, Natural Science and Technology, Okayama University）
* E-mail : pnjl7b2l@s.okayama-u.ac.jp

# 参考文献
