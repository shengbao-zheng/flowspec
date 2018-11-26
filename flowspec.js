var router = '10.0.0.141';
var id = '10.0.0.70';
var as = 65141;
var thresh = 1000;
var block_minutes = 1;

setFlow('udp_target',{keys:'ipdestination,udpsourceport',value:'frames'});

setThreshold('attack',{metric:'udp_target', value:thresh, byFlow:true});

bgpAddNeighbor(router,as,id,{flowspec:true});

var controls = {};
setEventHandler(function(evt) {
  var key = evt.flowKey;
  if(controls[key]) return;

  var now = (new Date()).getTime();
  var [ip,port] = key.split(',');
  var flow = {
    'match':{
      'protocol':'=17',
      'source-port':'='+port,
      'destination': ip
    },
    'then': {'traffic-rate':0}
  };
  controls[key] = {time:now, target: ip, port: port, flow:flow};
  bgpAddFlow(router, flow);
  logInfo('block target='+ip+' port='+port);  
},['attack']);

setIntervalHandler(function() {
  var now = (new Date()).getTime();
  for(var key in controls) {
    if(now - controls[key].time < 1000 * 60 * block_minutes) continue;
    var control = controls[key];
    delete controls[key];
    bgpRemoveFlow(router,control.flow);
    logInfo('allow target='+control.target+' port='+control.port);
  }
});
