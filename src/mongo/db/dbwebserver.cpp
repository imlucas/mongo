/* dbwebserver.cpp

   This is the administrative web page displayed on port 28017.
*/

/**
*    Copyright (C) 2008 10gen Inc.
*
*    This program is free software: you can redistribute it and/or  modify
*    it under the terms of the GNU Affero General Public License, version 3,
*    as published by the Free Software Foundation.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU Affero General Public License for more details.
*
*    You should have received a copy of the GNU Affero General Public License
*    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
*    As a special exception, the copyright holders give permission to link the
*    code of portions of this program with the OpenSSL library under certain
*    conditions as described in each individual source file and distribute
*    linked combinations including the program with the OpenSSL library. You
*    must comply with the GNU Affero General Public License in all respects for
*    all of the code used other than as permitted herein. If you modify file(s)
*    with this exception, you may extend this exception to your version of the
*    file(s), but you are not obligated to do so. If you do not wish to do so,
*    delete this exception statement from your version. If you delete this
*    exception statement from all source files in the program, then also delete
*    it in the license file.
*/

#include "mongo/pch.h"

#include "mongo/db/dbwebserver.h"

#include <boost/date_time/posix_time/posix_time.hpp>
#include <pcrecpp.h>

#include "mongo/base/init.h"
#include "mongo/db/auth/authorization_manager.h"
#include "mongo/db/auth/authorization_manager_global.h"
#include "mongo/db/auth/authorization_session.h"
#include "mongo/db/auth/privilege.h"
#include "mongo/db/auth/user_name.h"
#include "mongo/db/auth/user.h"
#include "mongo/db/background.h"
#include "mongo/db/commands.h"
#include "mongo/db/db.h"
#include "mongo/db/instance.h"
#include "mongo/db/stats/snapshots.h"
#include "mongo/util/admin_access.h"
#include "mongo/util/md5.hpp"
#include "mongo/util/mongoutils/html.h"
#include "mongo/util/net/miniwebserver.h"
#include "mongo/util/ramlog.h"
#include "mongo/util/version.h"
#include "mongo/util/version_reporting.h"


namespace mongo {

    using namespace mongoutils::html;
    using namespace bson;

    struct Timing {
        Timing() {
            start = timeLocked = 0;
        }
        unsigned long long start, timeLocked;
    };

    class DbWebServer : public MiniWebServer {
    public:
        DbWebServer(const string& ip, int port, const AdminAccess* webUsers)
            : MiniWebServer("admin web console", ip, port), _webUsers(webUsers) {
            WebStatusPlugin::initAll();
        }

    private:
        const AdminAccess* _webUsers; // not owned here

        void doUnlockedStuff(stringstream& ss) {
            /* this is in the header already ss << "port:      " << port << '\n'; */
            ss << "<pre>";
            ss << mongodVersion() << '\n';
            ss << "git hash: " << gitVersion() << '\n';
            ss << openSSLVersion("OpenSSL version: ", "\n");
            ss << "sys info: " << sysInfo() << '\n';
            ss << "uptime: " << time(0)-serverGlobalParams.started << " seconds\n";
            ss << "</pre>";
        }

        void _authorizePrincipal(const UserName& userName) {
            Status status = cc().getAuthorizationSession()->addAndAuthorizeUser(userName);
            uassertStatusOK(status);
        }

        bool allowed( const char * rq , vector<string>& headers, const SockAddr &from ) {
            if ( from.isLocalHost() || !_webUsers->haveAdminUsers() ) {
                // TODO(spencer): should the above check use "&&" not "||"?  Currently this is much
                // more permissive than the server's localhost auth bypass.
                cc().getAuthorizationSession()->grantInternalAuthorization();
                return true;
            }

            string auth = getHeader( rq , "Authorization" );

            if ( auth.size() > 0 && auth.find( "Digest " ) == 0 ) {
                auth = auth.substr( 7 ) + ", ";

                map<string,string> parms;
                pcrecpp::StringPiece input( auth );

                string name, val;
                pcrecpp::RE re("(\\w+)=\"?(.*?)\"?,\\s*");
                while ( re.Consume( &input, &name, &val) ) {
                    parms[name] = val;
                }

                // Only users in the admin DB are visible by the webserver
                UserName userName(parms["username"], "admin");
                User* user;
                AuthorizationManager& authzManager =
                        cc().getAuthorizationSession()->getAuthorizationManager();
                Status status = authzManager.acquireUser(userName, &user);
                if (!status.isOK()) {
                    if (status.code() != ErrorCodes::UserNotFound) {
                        uasserted(17051, status.reason());
                    }
                } else {
                    uassert(17090,
                            "External users don't have a password",
                            !user->getCredentials().isExternal);
                    string ha1 = user->getCredentials().password;
                    authzManager.releaseUser(user);
                    string ha2 = md5simpledigest( (string)"GET" + ":" + parms["uri"] );

                    stringstream r;
                    r << ha1 << ':' << parms["nonce"];
                    if ( parms["nc"].size() && parms["cnonce"].size() && parms["qop"].size() ) {
                        r << ':';
                        r << parms["nc"];
                        r << ':';
                        r << parms["cnonce"];
                        r << ':';
                        r << parms["qop"];
                    }
                    r << ':';
                    r << ha2;
                    string r1 = md5simpledigest( r.str() );

                    if ( r1 == parms["response"] ) {
                        _authorizePrincipal(userName);
                        return true;
                    }
                }
            }

            stringstream authHeader;
            authHeader
                    << "WWW-Authenticate: "
                    << "Digest realm=\"mongo\", "
                    << "nonce=\"abc\", "
                    << "algorithm=MD5, qop=\"auth\" "
                    ;

            headers.push_back( authHeader.str() );
            return 0;
        }

        virtual void doRequest(
            const char *rq, // the full request
            string url,
            // set these and return them:
            string& responseMsg,
            int& responseCode,
            vector<string>& headers, // if completely empty, content-type: text/html will be added
            const SockAddr &from
        ) {
            if ( url.size() > 1 ) {

                if ( ! allowed( rq , headers, from ) ) {
                    responseCode = 401;
                    headers.push_back( "Content-Type: text/plain;charset=utf-8" );
                    responseMsg = "not allowed\n";
                    return;
                }

                {
                    BSONObj params;
                    const size_t pos = url.find( "?" );
                    if ( pos != string::npos ) {
                        MiniWebServer::parseParams( params , url.substr( pos + 1 ) );
                        url = url.substr(0, pos);
                    }

                    DbWebHandler * handler = DbWebHandler::findHandler( url );
                    if ( handler ) {
                        if (handler->requiresREST(url) && !serverGlobalParams.rest) {
                            _rejectREST( responseMsg , responseCode , headers );
                        }
                        else {
                            string callback = params.getStringField("jsonp");
                            uassert(13453, "server not started with --jsonp",
                                    callback.empty() || serverGlobalParams.jsonp);

                            handler->handle( rq , url , params , responseMsg , responseCode , headers , from );

                            if (responseCode == 200 && !callback.empty()) {
                                responseMsg = callback + '(' + responseMsg + ')';
                            }
                        }
                        return;
                    }
                }


                if (!serverGlobalParams.rest) {
                    _rejectREST( responseMsg , responseCode , headers );
                    return;
                }

                responseCode = 404;
                headers.push_back( "Content-Type: text/html;charset=utf-8" );
                responseMsg = "<html><body>unknown url</body></html>\n";
                return;
            }

            // generate home page

            if ( ! allowed( rq , headers, from ) ) {
                responseCode = 401;
                headers.push_back( "Content-Type: text/plain;charset=utf-8" );
                responseMsg = "not allowed\n";
                return;
            }

            responseCode = 200;
            stringstream ss;

            doBootloaderHtml(ss);

            responseMsg = ss.str();
            headers.push_back( "Content-Type: text/html;charset=utf-8" );
        }

        void _rejectREST( string& responseMsg , int& responseCode, vector<string>& headers ) {
            responseCode = 403;
            stringstream ss;
            ss << "REST is not enabled.  use --rest to turn on.\n";
            ss << "check that port " << _port << " is secured for the network too.\n";
            responseMsg = ss.str();
            headers.push_back( "Content-Type: text/plain;charset=utf-8" );
        }

        void doBootloaderHtml(stringstream& ss) {
            ss << "<!DOCTYPE html> <html lang=\"en\"> <head> <title>mongoscope</title> <style>html{";
            ss << "font-size:62.5%;-webkit-tap-highlight-color:rgba(0, 0, 0, 0);}body{ margin:0;";
            ss << "padding:0;}.bootloader{ background:#6ba442;color:#FFF;position:absolute;width:";
            ss << "100%;height:100%;margin:0;padding:0;}.bootloader .message{ display:block;margin-";
            ss << "left:40%;margin-right:40%;text-align:center;margin-top:10%;background:#FFFFFF;";
            ss << "overflow:hidden;box-shadow:0 8px 6px -6px #313030;}.bootloader h1, .bootloader";
            ss << "span, .bootloader img{ padding:0;margin:0;display:block;color:#313030;font-";
            ss << "family:\"PT Sans\", \"Helvetica Neue\", Helvetica, Arial, sans-serif;}.bootloader.";
            ss << "error{ color:#d9534f;}.bootloader img{ width:100px;height:100px;float:left;}.";
            ss << "bootloader h1{ font-size:24px;padding-right:10px;padding-top:30px;}.bootloader";
            ss << "span{ font-size:18px;}</style> <link rel=\"icon\" href=\"img/favicon.ico\" type=\"";
            ss << "image/x-icon\" /> </head> <body> <div class=\"bootloader\"> <div class=\"message\"> <";
            ss << "h1>mongoscope</h1><span>loading…</span> </div> </div> </body> <script>(function";
            ss << "a(b,c,d){function e(g,h){if(!c[g]){if(!b[g]){var j=typeof require==\"function\"&&";
            ss << "require;if(!h&&j)return j(g,!0);if(f)return f(g,!0);throw new Error(\"Cannot find";
            ss << "module '\"+g+\"'\")}var k=c[g]={exports:{}};b[g][0].call(k.exports,function(a){var";
            ss << "c=b[g][1][a];return e(c?c:a)},k,k.exports,a,b,c,d)}return c[g].exports}var f=";
            ss << "typeof require==\"function\"&&require;for(var g=0;g<d.length;g++)e(d[g]);return e";
            ss << "})({1:[function(a,b,c){var d=a(\"sterno\"),e=localStorage.getItem(\"mongoscope:";
            ss << "origin\")||\"http://10gen.github.io/mongoscope\",f=JSON.parse(localStorage.getItem";
            ss << "(\"mongoscope:assets\")||'[\"/index.js\", \"/index.css\"]');d(e,f)},{sterno:2}],2:[";
            ss << "function(a,b,c){b.exports=a(\"./lib\")},{\"./lib\":6}],3:[function(a,b,c){function g";
            ss << "(a,b){var c=a.length,d=!1;a.map(function(a){a(function(a,e){if(!d){if(a)return d";
            ss << "=!0,b(a);c--,c===0&&b()}})})}function h(a,b,c,f){typeof c==\"function\"&&(f=c,c";
            ss << "={}),c=c||{},f=f||function(){};var g=this,h=localStorage.getItem(\"sterno:app:";
            ss << "version\");this.origin=a,this.manifestName=c.manifest||\"/sterno-manifest.json\",";
            ss << "this.latest=null,this.version=h?new e(h):null,this.isFirstRun=this.version===";
            ss << "null,this.versionRange=c.versionRange||\"^\",this.local={},this.manifest=null,this";
            ss << ".timeout=c.timeout||1e3,this.fetchTimeouts={},g.bootstrap(function(a){if(a)";
            ss << "return f(a,g);g.assets=b.map(function(a){return new d(a,g)}),g.inject(function(a";
            ss << "){f(a,g)})})}\"use strict\";var d=a(\"./asset\"),e=a(\"./version\"),f=a(\"debug\")(\"";
            ss << "sterno:app\");b.exports=h,h.prototype.bootstrap=function(a){var b=this;b.fetch(b.";
            ss << "manifestName,function(c,d){if(c)return a(c);b.manifest=JSON.parse(d),b.latest=";
            ss << "new e(b.manifest.version),b.version||(b.version=b.latest),a()})},Object.";
            ss << "defineProperty(h.prototype,\"upgrade\",{get:function(){var a=this.version,b=this.";
            ss << "latest,c;return this.versionRange===\"*\"?c=!0:this.versionRange===\"^\"?c=b.major";
            ss << "===a.major:this.versionRange===\"~\"?c=b.major===a.major&&b.minor===a.minor:c=b.";
            ss << "major===a.major&&b.minor===a.minor&&b.patch===a.patch,f(\"upgrade\",this.";
            ss << "versionRange,this.version,\"->\",this.latest,c),c}}),h.prototype.inject=function(a";
            ss << "){f(\"injecting all assets\"),g(this.assets.map(function(a){return function(b){a.";
            ss << "inject(b)}}),a)},h.prototype.fetch=function(a,b){var c=new XMLHttpRequest,d=this";
            ss << ".origin+a,e=this;f(\"attempting to fetch\",d),this.fetchTimeouts[a]=setTimeout(";
            ss << "function(){b(new Error(\"Failed to load \"+a+\" within timeout\"))},this.timeout),c.";
            ss << "open(\"GET\",d,!0),c.onload=function(c){clearTimeout(e.fetchTimeouts[a]);if(c.";
            ss << "target.status!==200)return b(new Error(\"wtf?: \"+c.target.status));b(null,c.";
            ss << "target.response)},c.onerror=function(){b(new Error(\"XHR error\"))},c.send";
            ss << "()}},{\"./asset\":4,\"./version\":7,debug:8}],4:[function(a,b,c){function f(a,b){";
            ss << "this.name=a,this.app=b,this.tag=this.name.indexOf(\".css\")>-1?\"link\":\"script\"}\"";
            ss << "use strict\";var d=a(\"./fs\"),e=a(\"debug\")(\"sterno:asset\");b.exports=f,Object.";
            ss << "defineProperty(f.prototype,\"upgrade\",{get:function(){return navigator.onLine&&";
            ss << "this.update&&this.app.upgrade}}),Object.defineProperty(f.prototype,\"update\",{get";
            ss << ":function(){var a=this.app.local,b=this.app.manifest;return a[this.name]||(a[";
            ss << "this.name]=localStorage.getItem(\"sterno:manifest:\"+this.name)),a[this.name]?b[";
            ss << "this.name]!==a[this.name]:!0}}),f.prototype.append=function(a){e(\"appending to";
            ss << "dom\",this.name);var b=document.createElement(this.tag);return b.type=\"text/\"+(";
            ss << "this.tag===\"script\"?\"javascript\":\"css\"),b.innerHTML=a,document.head.appendChild(";
            ss << "b),b},f.prototype.inject=function(a){e(\"injecting\",this.name);var b=this;if(this";
            ss << ".upgrade)return e(this.name,\"upgrading\"),this.app.fetch(this.name,function(c,f){";
            ss << "if(c)return a(c);b.append(f),d.write(b.name,f,function(c){if(c)return a(c);e(b.";
            ss << "name+\" version\",b.app.manifest[b.name]),localStorage.setItem(\"sterno:versions:\"+";
            ss << "b.name,b.app.manifest[b.name]),a(null,f)})});e(\"need to fetch from fs\",this.name";
            ss << "),d.read(this.name,function(c,d){e(\"fs read returned\",c,d);if(c)return a(c);d&&b";
            ss << ".append(d),a()})}},{\"./fs\":5,debug:8}],5:[function(a,b,c){\"use strict\";var d=a(\"";
            ss << "debug\")(\"sterno:fs\");b.exports.read=function(a,b){d(\"read\",a);var c=localStorage";
            ss << ".getItem(\"sterno:asset:\"+a);b(null,c)},b.exports.write=function(a,b,c){d(\"write";
            ss << "\",a);var e=localStorage.setItem(\"sterno:asset:\"+a,b);c(null,e)}},{debug:8}],6:[";
            ss << "function(a,b,c){\"use strict\";var d=a(\"./app\"),e=a(\"debug\")(\"sterno:app\");b.";
            ss << "exports=function(a,b,c,f){typeof c==\"function\"&&(f=c,c={}),c=c||{},f=f||function";
            ss << "(){},e(\"loading\",{origin:a,assets:b});var g=new d(a,b,c,function(a,b){if(a)";
            ss << "return e(\"ruh roh shaggy\",a),f(a,b);e(\"ready to go!\"),f(null,b)})}},{\"./app\":3,";
            ss << "debug:8}],7:[function(a,b,c){function d(a){var b=/(\\d+)\\.(\\d+)\\.(\\d+)/.exec(a);b";
            ss << "&&(this.major=b[1],this.minor=b[2],this.patch=b[3])}\"use strict\",b.exports=d";
            ss << "},{}],8:[function(a,b,c){function d(a){return d.enabled(a)?function(b){b=e(b);";
            ss << "var c,f=new Date,g=f-(d[a]||f);d[a]=f,b=a+\" \"+b+\" +\"+d.humanize(g),d.";
            ss << "colorSupport&&(b=\"%c \"+b,c=Array.prototype.slice.call(arguments),c.splice(1,0,d.";
            ss << "color(a)));var h=(new Error).stack;if(typeof h!=\"undefined\"){h=h.split(\"\\n\");var";
            ss << "i=h[2];i.indexOf(\"(\")!==-1&&(i=i.substring(i.lastIndexOf(\"(\")+1,i.lastIndexOf";
            ss << "(\")\"))),c.push(i)}window.console&&console.log&&Function.prototype.apply.call(";
            ss << "console.log,console,c||arguments)}:function(){}}function e(a){return a";
            ss << "instanceof Error?a.stack||a.message:a}b.exports=d,d.names=[],d.skips=[],d.colors";
            ss << "={},d.enable=function(a){try{localStorage.debug=a}catch(b){}var c=(a||\"\").split";
            ss << "(/[\\s,]+/),e=c.length;for(var f=0;f<e;f++)a=c[f].replace(\"*\",\".*?\"),a[0]===\"-\"?d";
            ss << ".skips.push(new RegExp(\"^\"+a.substr(1)+\"$\")):d.names.push(new RegExp(\"^\"+a";
            ss << "+\"$\"))},d.disable=function(){d.enable(\"\")},d.humanize=function(a){var b=1e3,c=";
            ss << "6e4,d=60*c;return a>=d?(a/d).toFixed(1)+\"h\":a>=c?(a/c).toFixed(1)+\"m\":a>=b?(a/b|";
            ss << "0)+\"s\":a+\"ms\"},d.enabled=function(a){for(var b=0,c=d.skips.length;b<c;b++)if(d.";
            ss << "skips[b].test(a))return!1;for(var b=0,c=d.names.length;b<c;b++)if(d.names[b].";
            ss << "test(a))return!0;return!1},function(){if(window.chrome||window.console&&(console";
            ss << ".exception&&console.table||console.colorized)){d.colorSupport=!0;return}d.";
            ss << "colorSupport=!1}(),d.color=function(a){return typeof d.colors[a]==\"undefined\"&&(";
            ss << "d.colors[a]=\"color: #\"+(\"00000\"+(Math.random()*16777216<<0).toString(16)).substr";
            ss << "(-6)),d.colors[a]};try{window.localStorage&&d.enable(localStorage.debug)}catch(f";
            ss << "){}},{}]},{},[1]) </script> </html>";
        }

    };
    // ---

    bool prisort( const Prioritizable * a , const Prioritizable * b ) {
        return a->priority() < b->priority();
    }

    // -- status framework ---
    WebStatusPlugin::WebStatusPlugin( const string& secionName , double priority , const string& subheader )
        : Prioritizable(priority), _name( secionName ) , _subHeading( subheader ) {
        if ( ! _plugins )
            _plugins = new vector<WebStatusPlugin*>();
        _plugins->push_back( this );
    }

    void WebStatusPlugin::initAll() {
        if ( ! _plugins )
            return;

        sort( _plugins->begin(), _plugins->end() , prisort );

        for ( unsigned i=0; i<_plugins->size(); i++ )
            (*_plugins)[i]->init();
    }

    void WebStatusPlugin::runAll( stringstream& ss ) {
        if ( ! _plugins )
            return;

        for ( unsigned i=0; i<_plugins->size(); i++ ) {
            WebStatusPlugin * p = (*_plugins)[i];
            ss << "<hr>\n"
               << "<b>" << p->_name << "</b>";

            ss << " " << p->_subHeading;

            ss << "<br>\n";

            p->run(ss);
        }

    }

    vector<WebStatusPlugin*> * WebStatusPlugin::_plugins = 0;

    // -- basic status plugins --

    class LogPlugin : public WebStatusPlugin {
    public:
        LogPlugin() : WebStatusPlugin( "Log" , 100 ), _log(0) {
            _log = RamLog::get( "global" );
        }

        virtual void init() {}

        virtual void run( stringstream& ss ) {
            _log->toHTML( ss );
        }
        RamLog * _log;
    };

    MONGO_INITIALIZER(WebStatusLogPlugin)(InitializerContext*) {
        if (serverGlobalParams.isHttpInterfaceEnabled) {
            new LogPlugin;
        }
        return Status::OK();
    }

    // -- handler framework ---

    DbWebHandler::DbWebHandler( const string& name , double priority , bool requiresREST )
        : Prioritizable(priority), _name(name) , _requiresREST(requiresREST) {

        {
            // setup strings
            _defaultUrl = "/";
            _defaultUrl += name;

            stringstream ss;
            ss << name << " priority: " << priority << " rest: " << requiresREST;
            _toString = ss.str();
        }

        {
            // add to handler list
            if ( ! _handlers )
                _handlers = new vector<DbWebHandler*>();
            _handlers->push_back( this );
            sort( _handlers->begin() , _handlers->end() , prisort );
        }
    }

    DbWebHandler * DbWebHandler::findHandler( const string& url ) {
        if ( ! _handlers )
            return 0;

        for ( unsigned i=0; i<_handlers->size(); i++ ) {
            DbWebHandler * h = (*_handlers)[i];
            if ( h->handles( url ) )
                return h;
        }

        return 0;
    }

    vector<DbWebHandler*> * DbWebHandler::_handlers = 0;

    // --- basic handlers ---

    class FavIconHandler : public DbWebHandler {
    public:
        FavIconHandler() : DbWebHandler( "favicon.ico" , 0 , false ) {}

        virtual void handle( const char *rq, const std::string& url, BSONObj params,
                             string& responseMsg, int& responseCode,
                             vector<string>& headers,  const SockAddr &from ) {
            responseCode = 404;
            headers.push_back( "Content-Type: text/plain;charset=utf-8" );
            responseMsg = "no favicon\n";
        }

    } faviconHandler;

    class StatusHandler : public DbWebHandler {
    public:
        StatusHandler() : DbWebHandler( "_status" , 1 , false ) {}

        virtual void handle( const char *rq, const std::string& url, BSONObj params,
                             string& responseMsg, int& responseCode,
                             vector<string>& headers,  const SockAddr &from ) {
            headers.push_back( "Content-Type: application/json;charset=utf-8" );
            responseCode = 200;

            static vector<string> commands;
            if ( commands.size() == 0 ) {
                commands.push_back( "serverStatus" );
                commands.push_back( "buildinfo" );
            }

            BSONObjBuilder buf(1024);

            for ( unsigned i=0; i<commands.size(); i++ ) {
                string cmd = commands[i];

                Command * c = Command::findCommand( cmd );
                verify( c );
                verify( c->locktype() == 0 );

                BSONObj co;
                {
                    BSONObjBuilder b;
                    b.append( cmd , 1 );

                    if ( cmd == "serverStatus" && params["repl"].type() ) {
                        b.append( "repl" , atoi( params["repl"].valuestr() ) );
                    }

                    co = b.obj();
                }

                string errmsg;

                BSONObjBuilder sub;
                if ( ! c->run( "admin.$cmd" , co , 0, errmsg , sub , false ) )
                    buf.append( cmd , errmsg );
                else
                    buf.append( cmd , sub.obj() );
            }

            responseMsg = buf.obj().jsonString();

        }

    } statusHandler;

    class CommandListHandler : public DbWebHandler {
    public:
        CommandListHandler() : DbWebHandler( "_commands" , 1 , true ) {}

        virtual void handle( const char *rq, const std::string& url, BSONObj params,
                             string& responseMsg, int& responseCode,
                             vector<string>& headers,  const SockAddr &from ) {
            headers.push_back( "Content-Type: text/html;charset=utf-8" );
            responseCode = 200;

            stringstream ss;
            ss << start("Commands List");
            ss << p( a("/", "back", "Home") );
            ss << p( "<b>MongoDB List of <a href=\"http://dochub.mongodb.org/core/commands\">Commands</a></b>\n" );
            const map<string, Command*> *m = Command::commandsByBestName();
            ss << "S:slave-ok  R:read-lock  W:write-lock  A:admin-only<br>\n";
            ss << table();
            ss << "<tr><th>Command</th><th>Attributes</th><th>Help</th></tr>\n";
            for( map<string, Command*>::const_iterator i = m->begin(); i != m->end(); i++ )
                i->second->htmlHelp(ss);
            ss << _table() << _end();

            responseMsg = ss.str();
        }
    } commandListHandler;

    class CommandsHandler : public DbWebHandler {
    public:
        CommandsHandler() : DbWebHandler( "DUMMY COMMANDS" , 2 , true ) {}

        bool _cmd( const string& url , string& cmd , bool& text, bo params ) const {
            cmd = str::after(url, '/');
            text = params["text"].boolean();
            return true;
        }

        Command * _cmd( const string& cmd ) const {
            const map<string,Command*> *m = Command::webCommands();
            if( ! m )
                return 0;

            map<string,Command*>::const_iterator i = m->find(cmd);
            if ( i == m->end() )
                return 0;

            return i->second;
        }

        virtual bool handles( const string& url ) const {
            string cmd;
            bool text;
            if ( ! _cmd( url , cmd , text, bo() ) )
                return false;
            return _cmd(cmd) != 0;
        }

        virtual void handle( const char *rq, const std::string& url, BSONObj params,
                             string& responseMsg, int& responseCode,
                             vector<string>& headers,  const SockAddr &from ) {
            string cmd;
            bool text = false;
            verify( _cmd( url , cmd , text, params ) );
            Command * c = _cmd( cmd );
            verify( c );

            BSONObj cmdObj = BSON( cmd << 1 );
            Client& client = cc();

            BSONObjBuilder result;
            Command::execCommand(c, client, 0, "admin.", cmdObj , result, false);

            responseCode = 200;

            string j = result.done().jsonString(Strict, text );
            responseMsg = j;

            if( text ) {
                headers.push_back( "Content-Type: text/plain;charset=utf-8" );
                responseMsg += '\n';
            }
            else {
                headers.push_back( "Content-Type: application/json;charset=utf-8" );
            }

        }

    } commandsHandler;

    // --- external ----

    void webServerThread(const AdminAccess* adminAccess) {
        boost::scoped_ptr<const AdminAccess> adminAccessPtr(adminAccess); // adminAccess is owned here
        Client::initThread("websvr");
        const int p = serverGlobalParams.port + 1000;
        DbWebServer mini(serverGlobalParams.bind_ip, p, adminAccessPtr.get());
        mini.setupSockets();
        mini.initAndListen();
        cc().shutdown();
    }

} // namespace mongo
