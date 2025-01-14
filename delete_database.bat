@echo off
rem Check if the database file exists
if exist calendar.db (
    del calendar.db
    echo Database deleted successfully.
) else (
    echo No database file found to delete.
)
pause