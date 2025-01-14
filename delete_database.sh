#!/bin/bash

# データベースファイルの名前
DB_FILE="./calendar.db"

# データベース削除確認メッセージ
echo "This will permanently delete the database file: $DB_FILE"
read -p "Are you sure you want to continue? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Operation cancelled."
    exit 0
fi

# データベースファイルが存在するか確認
if [ -f "$DB_FILE" ]; then
    # ファイルを削除
    rm "$DB_FILE"
    if [ $? -eq 0 ]; then
        echo "Database file '$DB_FILE' deleted successfully."
    else
        echo "Failed to delete the database file."
        exit 1
    fi
else
    echo "Database file '$DB_FILE' does not exist."
    exit 1
fi
