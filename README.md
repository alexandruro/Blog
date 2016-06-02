# Multi-user Blog
A blog made for the udacity nanodegree. It has support for multiple users, liking posts, editing and deleting posts and comments (only by the author), etc.
It is built using and for [Google App Engine](https://cloud.google.com/appengine/).

## How to run

### Using App Engine

  If you’re using the Google App Engine Launcher, you can set up the application by selecting the File menu, Add Existing Application...,
then selecting the app directory. Select the application in the app list, click the Run button to start the application, 
then click the Browse button to view it.
  If you’re not using Google App Engine Launcher, start the web server with the following command, giving it the path to the 
  app directory:

```
google_appengine/dev_appserver.py <app-folder>
```

The web server is now running, listening for requests on port 8080. You can test the application by visiting the following URL in 
your web browser:

> [http://localhost:8080/](http://localhost:8080/)

### Outside of App Engine (might not work properly)

To run outside of App Engine, you need to have a few libraries.

Installing them with pip:
```bash
$ pip install WebOb
$ pip install Paste
$ pip install webapp2
```

Or, using easy_install:
```bash
$ easy_install WebOb
$ easy_install Paste
$ easy_install webapp2
```

After these are installed, the application can be run like so:
```bash
$ python main.py
```

## Future updates
* sharing to social media
* better styling
