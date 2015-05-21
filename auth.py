#!/usr/bin/python

import Ice
import logging
import sys
import os
import MySQLdb as db
import warnings

from logging    import(debug,
            info,
            warning,
            critical,
            error,
            getLogger)
from threading import Timer
from systemd import journal

slicefile = "/usr/share/murmur/Murmur.ice"
loglevel = logging.DEBUG
logfile = 'murmur_auth.log'
iceSecret = ""
iceHost = "127.0.0.1"
icePort = "6502"
servers = []
fcgroups = ['210','231','26','28']
dbhost = 'ssd-db-1a'
dbport = '3306'
dbuser = 'gsfForums'
dbpw = ''
dbname = 'gsfForums'

watchdog = 30
authenticateFortifyResult = (-1, None, None)

warnings.filterwarnings('ignore')

mdbhost = '127.0.0.1'
mdbport = '3306'
mdbuser = 'gsfMurmur'
mdbpw = ''
mdbname = 'gsfMurmur'

def do_main_program():
    try:
        sql = "CREATE TABLE IF NOT EXISTS user_inf LIKE user_info"
        mumdbcon = db.connect(mdbhost,mdbuser,mdbpw,mdbname)
        curs = mumdbcon.cursor()
        curs.execute(sql)
        curs.close()
        mumdbcon.autocommit(True)
    except db.OperationalError as e:
        info("user_inf table exists, will not try to make.")

    try:
        forumdbcon = db.connect(dbhost,dbuser,dbpw,dbname)
    except db.OperationalError as e:
        error("Database error: {}".format(e))

    Ice.loadSlice('', ['-I'+Ice.getSliceDir(), slicefile])
    info("Ice Loaded")
    import Murmur

    class AuthenticatorApp(Ice.Application):
        def run(self, args):
            self.shutdownOnInterrupt()

            if not self.initializeIceConnection():
                return 1
            self.communicator().waitForShutdown()

            if self.interrupted():
                warning("Murmur-auth shutdown, removing callbacks.")
                self.meta.removeCallback(self.metacb)

            forumdbcon.close()
            mumdbcon.close()

            return 0

        def initializeIceConnection(self):
            ice = self.communicator()
            ice.getImplicitContext().put("secret",iceSecret)
            info("Connecting to server {} on port {}".format(iceHost,icePort))

            base = ice.stringToProxy('Meta:tcp -h {} -p {}'.format(iceHost,icePort))
            self.meta = Murmur.MetaPrx.uncheckedCast(base)

            adapter = ice.createObjectAdapterWithEndpoints('Callback.Client', 'tcp -h {}'.format(iceHost))
            adapter.activate()
            self.adapter = adapter

            metacbprx = adapter.addWithUUID(metaCallback(self))
            self.metacb = Murmur.MetaCallbackPrx.uncheckedCast(metacbprx)

#            authprx = adapter.addWithUUID(Authenticator())
#            self.auth = Murmur.ServerAuthenticatorPrx.uncheckedCast(authprx)

            return self.attachCallbacks(adapter)

        def checkConnection(self):
#            try:
#                if not self.attachCallbacks(self.adapter,quiet = not self.failedWatch):
#                    self.failedWatch = True
#                else:
#                    self.failedWatch = False
#            except Ice.Exception as e:
#                error("Failed connection check, will retry in next watchdog run ({})".format(watchdog))
#                debug(str(e))
#                self.watchFailed = True
#            self.watchdog = Timer(watchdog, self.checkConnection)
#            self.watchdog.start()
             return

        def attachCallbacks(self, adapter, quiet = False):
            try:
                self.meta.addCallback(self.metacb)
                for server in self.meta.getBootedServers():
                    if not servers or server.id() in servers:
                        serverprx = Murmur.ServerCallbackPrx.uncheckedCast(adapter.addWithUUID(ServerCallbackI(server, adapter)))
                        server.addCallback(serverprx)
                        server.setAuthenticator(Murmur.ServerAuthenticatorPrx.uncheckedCast(adapter.addWithUUID(Authenticator(int(server.id())))))

            except (Murmur.InvalidSecretException, Ice.UnknownUserException, Ice.ConnectionRefusedException) as e:
                if isinstance(e, Ice.ConnectionRefusedException):
                    error('Server refused connection')
                elif isinstance(e, Murmur.invalidSecretException) or isinstance(e, Ice.UnknownUserException) and (e.unknown == 'Murmur::InvalidSecretException'):
                    error('Invalid Secret')
                else:
                    raise e
                self.connected = False
                return False
            self.connected = True
            return True
    def fortifyIceFu(retval = None, exceptions = (Ice.Exception,)):
        def newdec(func):
            def newfunc(*args,**kws):
                try:
                    return func(*args,**kws)
                except Exception as e:
                    catch = True
                    for ex in exceptions:
                        if isinstance(e,ex):
                            catch = False
                            break
                    if catch:
                        critical("Unexpected exception caught")
                        critical(e)
                        return retval
                    raise
            return newfunc
        return newdec

    def checkSecret(func):
        if not iceSecret:
                return func
        def newfunc(*args,**kws):
            if 'current' in kws:
                current = kws["current"]
            else:
                current = args[-1]
            if not current or 'secret' not in current.ctx or current.ctx['secret'] != iceSecret:
                error("Server transmitted invalid secret. Possible injection attempt.")
                raise Murmur.InvalidSecretException()
            return func(*args,**kws)
        return newfunc                          

    class ServerCallbackI(Murmur.ServerCallback):
        def __init__(self, server, adapter):
            self.server = server
            self.contextR = Murmur.ServerContextCallbackPrx.uncheckedCast(adapter.addWithUUID(ServerContextCallbackI(server)))

        def userConnected(self, p, current = None):
            if p.address[10] == 255 and p.address[11] == 255:
                address = '.'.join(map(str,p.address[12:]))
            else:
                ip = []
                for i in p.address:
                    n = hex(i).split('x')[1]
                    if len(n) < 2:
                        n = "0"+n
                    ip.append(n)
                address = str(ip[0]+ip[1]+":"+ip[2]+ip[3]+":"+ip[4]+ip[5]+":"+ip[6]+ip[7]+":"+ip[8]+ip[9]+":"+ip[10]+ip[11]+":"+ip[12]+ip[13]+":"+ip[14]+ip[15])
            info("User {} connected from IP: {}".format(p.name, address))
#            sql = "SELECT mgroup_others FROM gsfForums.members WHERE member_id = %s"
#            con = db.connect(dbhost,dbuser,dbpw,dbname)
#            cur = con.cursor()
#            cur.execute(sql,(p.userid,))
#            res = cur.fetchone()
#            cur.close()
#            con.close()
#            if res:
#                groups = res[0].split(',')
#                isFc = False
#                for g in fcgroups:
#                    if g in groups:
#                        isFc = True
#                if isFc:
#                    info("User {} is an FC, adding context callback".format(p.name))
#                    self.server.addContextCallback(p.session, "Buttes", "Dongues", self.contextR, Murmur.ContextChannel)

        def userDisconnected(self, p, current = None):
            info("User {} disconnected".format(p.name))

    class ServerContextCallbackI(Murmur.ServerContextCallback):
        def __init__(self, server):
            self.server = server
        def contextAction(self, action, p, session, chanid, current = None):
            info("Action: {}, User: {}, SessionID: {}, Channel ID: {}".format(action, p.name, session, chanid))

    class metaCallback(Murmur.MetaCallback):
        def __init__(self,app):
            Murmur.MetaCallback.__init__(self)
            self.app = app
        @fortifyIceFu()
        @checkSecret
        def started(self, server, current = None):
            if not servers or server.id() in servers:
                try:
                    server.setAuthenticator(app.auth)
                except (Murmur.InvalidSecretException, Ice.UnknownUserException) as e:
                    if hasattr(e, "unknown" and e.unknown != "Murmur:InvalidSecretException"):
                        raise e

                    error("invalid secret")
                    return()
        @fortifyIceFu()
        @checkSecret
        def stopped(self, server, current = None):
            if self.app.connected:
                try:
                    if not servers or server.id() in servers:
                        debug("Mumble server was stopped")
                except Ice.ConnectionRefusedException:
                    self.app.connected = False
            os._exit(1)

    class Authenticator(Murmur.ServerAuthenticator):
        texture_cache = {}
        def __init__(self,serverid):
            Murmur.ServerAuthenticator.__init__(self)
            self.sid = serverid

        @fortifyIceFu(authenticateFortifyResult)
        @checkSecret

        def authenticate(self, name, pw, certlist, certhash, strong, current = None):
            forumdbcon.ping(True)
            mumdbcon.ping(True)

            FALL_THROUGH = -2
            AUTH_REFUSED = -1
            serverID = 1
            info("Authentication attempt for user '{}', cert hash '{}'".format(name,certhash))

            if name == 'SuperUser':
                return(FALL_THROUGH,None,None)
            
            #Check to see if a certificate hash exists for this user
            
            if name.find(' - ') > -1:
                name = name.split(' - ')[1]
            name = name.title()
            sql = "SELECT lcase(u.name),u.user_id, ui.value FROM users u JOIN user_inf ui ON ui.user_id = u.user_id WHERE SUBSTR(u.name,LOCATE(' - ',u.name)+3) = %s AND ui.value = %s"
            try:
                cur2 = mumdbcon.cursor()
                cur2.execute(sql,(name,certhash))
                res1 = cur2.fetchone()
                cur2.close()

                if res1:
                    sql = "SELECT CONCAT(t.ticker,' - ',replace(m.name,'&#39;','\\'')) AS name, m.member_id, g.g_title, m.member_banned FROM gsfForums.members m \
    JOIN gsfGSOAR.mumble esa ON esa.member_id = m.member_id JOIN gsfForums.groups g ON FIND_IN_SET(g.g_id, CONCAT(m.mgroup_others,',',m.member_group_id))\
    JOIN gsfGSOAR.groupTickers t ON t.groupID = m.member_group_id \
    WHERE (m.member_id = %s) ORDER BY g_title"
                    try:
                        cur3 = forumdbcon.cursor()
                        cur3.execute(sql,(res1[1],))
                        res2 = cur3.fetchall()
                        cur3.close()
                        groups = []
                        uname = ''
                        member_id = 0
                        for name, memid, gTitle, banned in res2:
                            if banned == 1:
                                info("Banned user '{}' attempted to connect.".format(name))
                                return(AUTH_REFUSED,None,None)
                            uname = name
                            member_id = memid
                            if gTitle == 'Administrators':
                                groups.append("admin")
                                info("User '{}' is an admin, adding to admin group".format(name))
                            else:
                                groups.append(gTitle)
                        info("User '{}' Authenticated by certificate hash. Added to groups {}".format(uname,groups))
                        return(member_id,uname,groups)
                    except (db.Error, db.OperationalError) as e:
                        error("Database error: {}".format(str(e)))
                        return(FALL_THROUGH,None,None)
                else:
                #No cert hash found, must be a new user. Check uname and pw against forum/esa dbs
                    sql = "SELECT CONCAT(t.ticker,' - ',replace(m.name,'&#39;','\\'')) AS name, m.member_id, g.g_title, m.member_banned FROM gsfForums.members m \
    JOIN gsfGSOAR.mumble esa ON esa.member_id = m.member_id JOIN gsfForums.groups g ON FIND_IN_SET(g.g_id, CONCAT(m.mgroup_others,',',m.member_group_id))\
    JOIN gsfGSOAR.groupTickers t ON t.groupID = m.member_group_id \
    WHERE (m.name = replace(%s,'\\'','&#39;') OR (m.name = replace(SUBSTR(%s, LOCATE(' - ',%s)+3),'\\'','&#39;'))) AND esa.passwd = SHA1(%s) ORDER BY g.g_title;"
                    try:
                        cur = forumdbcon.cursor()
                        cur.execute(sql,(name,name,name,pw))
                        res = cur.fetchall()
                        cur.close()
                        if res:
                            groups = []
                            uname = ''
                            member_id = 0
                            for name, memid, gTitle, banned in res:
                                if banned == 1:
                                    info("Banned user '{}' attempted to connect.".format(name))
                                    return(AUTH_REFUSED,None,None)

                                uname = name
                                member_id = memid
                                if gTitle == 'Administrators':
                                    groups.append("admin")
                                    info("User '{}' is an admin, adding to admin group.".format(name))
                                else:
                                    groups.append(gTitle)
                            sql = "INSERT INTO `user_inf` (`server_id`, `user_id`, `key`, `value`) VALUES (%s, %s, %s, %s) ON DUPLICATE KEY UPDATE value = %s;"
                            try:
                                cur2 = mumdbcon.cursor()
                                cur2.execute(sql,(serverID,member_id,3,certhash,certhash))
                                info("This is the first time {} has connected, inserting cert hash into user_inf".format(name))
                                cur2.close()
                            except (db.Error, db.OperationalError) as e:
                                error("Database error: {}".format(str(e)))
                            info("User '{}' Authenticated by password. Added to groups {}".format(uname,groups))
                            return(member_id, uname, groups)
                        else:
                            info("Authentication failed for user '{}'. Password or certificate invalid. Cert hash: {}".format(name,certhash))
                            return(AUTH_REFUSED,None,None)
                    except (db.Error, db.OperationalError) as e:
                        error("Database error: {}".format(str(e)))
                        return(FALL_THROUGH,None,None)
            except (db.Error, db.OperationalError) as e:
                error("Database error: {}".format(str(e)))
                return(FALL_THROUGH,None,None)
        @fortifyIceFu((False,None))
        @checkSecret

        def getInfo(self, id, current = None):
            return(False, None)
        @fortifyIceFu(-2)
        @checkSecret
        def nameToId(self, name, current = None):
            FALL_THROUGH = -2
            return(FALL_THROUGH)
        @fortifyIceFu("")
        @checkSecret
        def idToName(self, id, current = None):
            FALL_THROUGH = ""
            return FALL_THROUGH
        @fortifyIceFu("")
        @checkSecret
        def registerUser(self, name, current = None):
            FALL_THROUGH = -2
            return FALL_THROUGH
        @fortifyIceFu(-1)
        @checkSecret
        def unregisterUser(self, id, current = None):
            FALL_THROUGH = -1
            return FALL_THROUGH
        @fortifyIceFu({})
        @checkSecret
        def getRegisteredUsers(self, filter, current = None):
            return {}
        @fortifyIceFu(-1)
        @checkSecret
        def setInfo(self, id, info, current = None):
            FALL_THROUGH = -1
            return FALL_THROUGH
        @fortifyIceFu(-1)
        @checkSecret
        def setTexture(self, id, texture, current = None):
            FALL_THROUGH = -1
            return FALL_THROUGH

    class CustomLogger(Ice.Logger):
        def __init__(self):
            Ice.Logger.__init__(self)
            self._log = getLogger("Ice")
        def _print(self, message):
            self._log.info(message)
        def trace(self, category, message):
            self._log.debug("Trace {}: {}".format(category,message))
        def info(self, message):
            self._log.info(message)
        def warning(self, message):
            self._log.warning(message)
        def error(self, message):
            self._log.error(message)

    info("Starting Auth")
    initdata = Ice.InitializationData()
    initdata.properties = Ice.createProperties([], initdata.properties)
    initdata.properties.setProperty('Ice.ThreadPool.Server.Size','5')
    initdata.properties.setProperty('Ice.ImplicitContext','Shared')
    initdata.logger = CustomLogger()

    app = AuthenticatorApp()
    state = app.main(sys.argv[:1], initData = initdata)

if __name__ == '__main__':
    logging.basicConfig(level = loglevel, format='%(levelname)s %(message)s', filename = logfile)
    logging.propagate = False
    logging.root.addHandler(journal.JournalHandler(SYSLOG_IDENTIFIER='murmur-auth'))
    do_main_program()
