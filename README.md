# dashboard
Dashboard is a Python app that runs Flask and a MySQL database. It is formatted in Bootstrap and my own CSS. Its features include:

**Login Screen**
A standard login screen. Uses BCrypt to verify password and backend validations. Users who attempt to view dashboard without logging in are booted back to this screen.

**Dashboard**
The dashboard screen monitors the activity of another given program, for my purposes I used a mule. The header displays whether all mules in the past twenty-four hours have run successfully. The Latest Mules column displays the time, success, and name of the twelve most recently run mules. The Latest Reports column displays number successes and failures in the past eight and twenty-four hours.

**Custom Report**
Custom Report allows users with permission level 2 or above to view latest mules or reports for a custom time frame. Custom Query allows users with permission level 8 or above to directly query the database. 

**Admin Panel**
Admin Panel allows users to view the names and permission levels of other users. Users with permission level 9 can create new users as well. 