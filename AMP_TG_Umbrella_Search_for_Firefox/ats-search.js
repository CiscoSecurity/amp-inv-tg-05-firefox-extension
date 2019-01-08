// Firefox Extension to perform search query to Cisco AMP Threat Grid Umbrella
// Shyue Hong Chuang <schuang@cisco.com>
// Cisco Systems
// Copyright 2017
// v0.0.12

chrome.storage.local.get({
   favGeo: 'us',
   favAMP: 'FQDN or IP'
}, function(items) {
   AMPPublicCloudGeo = items.favGeo;
   AMPPrivateCloudIP = items.favAMP;
});

function extractFQDN(url) {
    var fqdn;
    if (url.indexOf("://") > -1) {
        fqdn = url.split('/')[2];
    } else {
        fqdn = url.split('/')[0];
    }
    fqdn = fqdn.split(':')[0];
    return fqdn;
}

function sendSampleSearch(searchType,selectedText) {
 var serviceCall = 'https://panacea.threatgrid.com/search/samples?qtype=' + searchType + '&q=' + selectedText;
 chrome.tabs.create({url: serviceCall});
}

function sendSearch(searchType,selectedText) {
 var serviceCall = 'https://panacea.threatgrid.com/' + searchType + '/' + selectedText;
 chrome.tabs.create({url: serviceCall});
}

function sendAMPSearch(searchType,selectedText) {
 var serviceCall = 'https://console.amp.cisco.com/search?query=' + selectedText;
 chrome.tabs.create({url: serviceCall});
}

function sendAMPEUSearch(searchType,selectedText) {
 var serviceCall = 'https://console.eu.amp.cisco.com/search?query=' + selectedText;
 chrome.tabs.create({url: serviceCall});
}

function sendAMPPCSearch(searchType,selectedText) {
 var serviceCall = 'https://' + AMPPrivateCloudIP + '/search?query=' + selectedText;
 chrome.tabs.create({url: serviceCall});
}

function sendUmbrellaSearch(searchType,selectedText) {
 var serviceCall = 'https://investigate.umbrella.com/' + searchType + '/' + selectedText;
 chrome.tabs.create({url: serviceCall});
}

function sendUmbrellaDomainSearch(searchType,selectedText) {
 var serviceCall = 'https://investigate.umbrella.com/' + searchType + '/name/' + selectedText + '/view';
 chrome.tabs.create({url: serviceCall});
}

chrome.contextMenus.create(
 {
  title: "TG Search - Selected Text",
  contexts:["selection"], 
  onclick: function(info, tab) {
      var sText = info.selectionText;
      var contextHash = /(\b[0-9a-f]{32})([0-9a-f]{8})?([0-9a-f]{24})?\b/i;
      var contextIP =  /\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b/;
      var contextDomain = /([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}/i;
      if (contextHash.test(sText)) {
         sendSampleSearch('checksum',info.selectionText);
      } else if (contextIP.test(sText)) {
         sendSearch('ips',info.selectionText);
      } else if (contextDomain.test(sText)) {
         sendSearch('domains',info.selectionText);
      }
  }
  });

chrome.contextMenus.create(
 {
  title: "Umbrella Search - Selected Text",
  contexts:["selection"], 
  onclick: function(info, tab) {
      var sText = info.selectionText;
      var contextHash = /(\b[0-9a-f]{32})([0-9a-f]{8})?([0-9a-f]{24})?\b/i;
      var contextIP =  /\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b/;
      var contextDomain = /([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}/i;
      if (contextHash.test(sText)) {
         sendUmbrellaSearch('sample-view',info.selectionText);
      } else if (contextIP.test(sText)) {
         sendUmbrellaSearch('ip-view',info.selectionText);
      } else if (contextDomain.test(sText)) {
         sendUmbrellaDomainSearch('domain-view',info.selectionText);
      }
  }
 });

chrome.contextMenus.create(
 {
  title: "TG Search - url ", 
  contexts:["link"], 
  onclick: function(info, tab) {
      sendSampleSearch('url',info.linkUrl);
  }
 });

chrome.contextMenus.create(
 {
  title: "Umbrella Search - FQDN ", 
  contexts:["link"], 
  onclick: function(info, tab) {
      var fqdn = extractFQDN(info.linkUrl);
      sendUmbrellaDomainSearch('domain-view',fqdn);
  }
 });

chrome.contextMenus.create(
 {
     title: "AMP Console Search - Selected Text ", 
     contexts:["selection"], 
     onclick: function(info, tab) {
         var sText = info.selectionText;
         if (AMPPublicCloudGeo == 'us') {
            sendAMPSearch('us',info.selectionText);
         } else if (AMPPublicCloudGeo == 'eu') {
            sendAMPEUSearch('eu',info.selectionText);
         }
     }
 });

chrome.contextMenus.create(
 {
     title: "AMP EU Console Search - Selected Text ", 
     contexts:["selection"], 
     onclick: function(info, tab) {
         var sText = info.selectionText;
         alert ("NOTE: You can now define US or EU AMP Console in extension options.  This search entry will soon be deprecated in favor of the options configuration.");
         sendAMPEUSearch('eu',info.selectionText);
     }
 });

chrome.contextMenus.create(
 {
     title: "AMP Private Cloud Console Search - Selected Text ", 
     contexts:["selection"], 
     onclick: function(info, tab) {
         var sText = info.selectionText;
         if (AMPPrivateCloudIP == 'FQDN or IP' || AMPPrivateCloudIP == '') {
            alert("ERROR! Private Cloud not defined in extension options.");
         } else {
            sendAMPPCSearch('us',info.selectionText);
         }
     }
 });
