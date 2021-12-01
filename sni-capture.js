const argv = require('minimist')(process.argv.slice(2))
const fs = require('fs')
const chalk = require('chalk')
const https = require('https')

const pcap = require('pcap'),
    tcp_tracker = new pcap.TCPTracker(),
    pcap_session = pcap.createSession('', { filter: "dst port 443" });

tcp_tracker.on('session', function (session) {
    //   console.log("Start of session between " + session.src_name + " and " + session.dst_name);
    session.on('end', function (session) {
        //   console.log("End of TCP session between " + session.src_name + " and " + session.dst_name);
    });
});

function getSNI(buf) {
    // https://stackoverflow.com/questions/17832592/extract-server-name-indication-sni-from-tls-client-hello?newreg=e81bc029b51841e5a793f2babc9da27f
    var sni = null
        , regex = /^(?:[a-z0-9-]+\.)+[a-z]+$/i;
    for (var b = 0, prev, start, end, str; b < buf.length; b++) {
        if (prev === 0 && buf[b] === 0) {
            start = b + 2;
            end = start + buf[b + 1];
            if (start < end && end < buf.length) {
                str = buf.toString("utf8", start, end);
                if (regex.test(str)) {
                    sni = str.toLowerCase();
                    continue;
                }
            }
        }
        prev = buf[b];
    }
    return sni;
}


function checkHttps(host) {
    return new Promise((resolve, reject) => {
        var options = {
            host: host,
            port: 443,
            method: 'GET',
            rejectUnauthorized: false
        };

        var req = https.request(options, function (res) {
            var certificateInfo = res.connection.getPeerCertificate();
            var dateInfo = {
                valid_from: new Date(certificateInfo.valid_from),
                valid_to: new Date(certificateInfo.valid_to),
                subject:certificateInfo.subject.CN
            };
            // console.log(chalk.blue.inverse(host),dateInfo)
            resolve(dateInfo);
        });
        req.on('error', (err) => {
            reject(err);
        })
        req.end();
    })
}

let hostname_data = {}
let logfile = false

if (argv.log && typeof argv.log==='string') {
    console.log(chalk.green(`** output will be logged into ${argv.log}`))
    logfile=argv.log
}

pcap_session.on('packet', async function (raw_packet) {
    try {
        let packet = pcap.decode.packet(raw_packet);
        let { data } = packet.payload.payload.payload
        if (data) {
            var sniHostname = getSNI(data)
            var daddr = packet.payload.payload.daddr.toString()
            var saddr = packet.payload.payload.saddr.toString()
            var dport = packet.payload.payload.payload.dport
            if (sniHostname) {
                
                if (!hostname_data.hasOwnProperty(sniHostname)) {
                    hostname_data[sniHostname] = {seen:0}
                }

                if (!hostname_data[sniHostname].t) {
                    try {
                        let ssl_info = await checkHttps(sniHostname)
                        // console.log(ssl_info)
                        // check subject
                        if (sniHostname.search(new RegExp(".*"+ssl_info.subject+"$"))!==0) {
                            hostname_data[sniHostname].t = Date.now()
                            hostname_data[sniHostname].state = 'SSL'
                            hostname_data[sniHostname].details = chalk.red(`Subject Mismatch:${ssl_info.subject}`)
                        } else
                        // check date
                        if (ssl_info && ssl_info.valid_to && Date.now() < ssl_info.valid_to) {
                            hostname_data[sniHostname].t = Date.now()
                            hostname_data[sniHostname].state = 'SSL'
                            hostname_data[sniHostname].details = chalk.green('SSL VERIFIED')
                        }
                    } catch (_err) {
                        // errored
                        hostname_data[sniHostname].t = Date.now()
                        hostname_data[sniHostname].state = 'ERROR'
                        hostname_data[sniHostname].details = chalk.red(_err.errno)
                        // console.log(_err)
                    }
                } 
                
                if (hostname_data[sniHostname].state==='ERROR' && Date.now()-hostname_data[sniHostname].t>10*60*1000) {
                    // every 10 minute we can reset ERROR ed checks
                    console.log(`Reset Error of ${sniHostname}`)
                    delete hostname_data[sniHostname].t
                    return
                }
                hostname_data[sniHostname].seen++
                
                    
                let log_line = `${chalk.gray(new Date().toISOString())} SNI: ${saddr} -> ${daddr}:${dport} ${chalk.yellow(sniHostname)} (${hostname_data[sniHostname].details}) seen:${hostname_data[sniHostname].seen}`
                console.log(log_line)
                if (logfile) fs.appendFileSync(logfile,log_line+"\n")
            }
        }
    } catch (err2) {
        console.log(err2)
    }


    // tcp_tracker.track_packet(packet);
});


