var pcap = require('pcap'),
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
    for(var b = 0, prev, start, end, str; b < buf.length; b++) {
      if(prev === 0 && buf[b] === 0) {
        start = b + 2;
        end   = start + buf[b + 1];
        if(start < end && end < buf.length) {
          str = buf.toString("utf8", start, end);
          if(regex.test(str)) {
            sni = str;
            continue;
          }
        }
      }
      prev = buf[b];
    }
    return sni;
  }
  

pcap_session.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);
    let {data} = packet.payload.payload.payload
    if (data )
        {
            var x = getSNI(data)
            var daddr = packet.payload.payload.daddr.toString()
            var saddr = packet.payload.payload.saddr.toString()
            var dport = packet.payload.payload.payload.dport
            if (x) 
                console.log(`SNI Captured: ${saddr} -> ${daddr}:${dport} ${x}`)
            
        }
    tcp_tracker.track_packet(packet);
});


