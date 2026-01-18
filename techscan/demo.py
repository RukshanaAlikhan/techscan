"""
demo.py - Demo/Test Mode

Since we can't always access the internet, this module provides
sample HTML responses to test our detection logic.

This is also a great way to learn! You can see exactly what
patterns we're looking for.
"""

# Sample response that looks like a WordPress site
WORDPRESS_SITE = {
    'headers': {
        'Server': 'nginx/1.18.0',
        'X-Powered-By': 'PHP/8.1.2',
        'Content-Type': 'text/html; charset=UTF-8',
    },
    'html': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="generator" content="WordPress 6.4.2">
    <title>My WordPress Blog</title>
    <link rel="stylesheet" href="/wp-content/themes/theme/style.css">
    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
</head>
<body>
    <div id="page">
        <header>
            <h1>Welcome to My Blog</h1>
        </header>
        <main>
            <article>
                <p>This is a sample WordPress site.</p>
            </article>
        </main>
        <script src="/wp-includes/js/wp-embed.min.js"></script>
    </div>
</body>
</html>
    ''',
    'cookies': {}
}

# Sample response that looks like a React app with Bootstrap
REACT_APP = {
    'headers': {
        'Server': 'cloudflare',
        'CF-Ray': '1234567890abcdef-LAX',
        'CF-Cache-Status': 'HIT',
        'Content-Type': 'text/html; charset=UTF-8',
    },
    'html': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>React Application</title>
    <link rel="stylesheet" href="/static/css/bootstrap-5.3.2.min.css">
    <script src="/static/js/react.production.min.js"></script>
    <script src="/static/js/react-dom.production.min.js"></script>
</head>
<body>
    <div id="root" data-reactroot="">
        <nav class="navbar navbar-expand-lg">
            <div class="container">
                <a class="navbar-brand" href="/">My React App</a>
            </div>
        </nav>
        <div class="container">
            <h1>Welcome!</h1>
        </div>
    </div>
    <!-- Google Analytics -->
    <script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXXX"></script>
</body>
</html>
    ''',
    'cookies': {}
}

# Sample Angular application
ANGULAR_APP = {
    'headers': {
        'Server': 'Apache/2.4.52',
        'Content-Type': 'text/html; charset=UTF-8',
    },
    'html': '''
<!DOCTYPE html>
<html lang="en" ng-version="17.0.5">
<head>
    <meta charset="UTF-8">
    <title>Angular App</title>
    <link rel="stylesheet" href="/styles.css">
</head>
<body>
    <app-root _nghost-ng-c1234567890>
        <div _ngcontent-ng-c1234567890 class="main-content">
            <h1>Angular Application</h1>
        </div>
    </app-root>
    <script src="/runtime.js"></script>
    <script src="/main.js"></script>
</body>
</html>
    ''',
    'cookies': {}
}

# Sample Vue.js application
VUE_APP = {
    'headers': {
        'Server': 'nginx',
        'X-Powered-By': 'Express',
        'Content-Type': 'text/html; charset=UTF-8',
    },
    'html': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Vue App</title>
    <script src="https://unpkg.com/vue@3.4.5/dist/vue.global.js"></script>
</head>
<body>
    <div id="app" data-v-app="">
        <div data-v-1234abcd class="container">
            <h1>Vue.js Application</h1>
        </div>
    </div>
</body>
</html>
    ''',
    'cookies': {}
}

# Sample Laravel application  
LARAVEL_APP = {
    'headers': {
        'Server': 'Apache/2.4.52',
        'X-Powered-By': 'PHP/8.2.0',
        'Content-Type': 'text/html; charset=UTF-8',
    },
    'html': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="csrf-token" content="abc123xyz">
    <title>Laravel App</title>
    <link rel="stylesheet" href="/css/app.css">
</head>
<body>
    <div id="app">
        <h1>Welcome to Laravel</h1>
    </div>
    <script src="/js/app.js"></script>
</body>
</html>
    ''',
    'cookies': {
        'laravel_session': 'eyJpdiI6Ijk...',
        'XSRF-TOKEN': 'eyJpdiI6Im...'
    }
}

# Dictionary of all demo sites
DEMO_SITES = {
    'wordpress': WORDPRESS_SITE,
    'react': REACT_APP,
    'angular': ANGULAR_APP,
    'vue': VUE_APP,
    'laravel': LARAVEL_APP,
}


def get_demo_site(name):
    """Get a demo site by name"""
    return DEMO_SITES.get(name.lower())


def list_demo_sites():
    """List available demo sites"""
    return list(DEMO_SITES.keys())