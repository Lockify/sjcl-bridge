if (typeof lockify == 'undefined') {
    lockify = {
        
    };
}
if (typeof lockify.sjclBridge == 'undefined') {
    lockify.sjclBridge = {
        encrypt: {},
        decrypt: {},
        throwEvent: function (eventName, extraArgs) {
            if ($) {
                if (typeof extraArgs != 'undefined') {
                    $(document).trigger(eventName, extraArgs);
                } else {
                    $(document).trigger(eventName);
                }
            } else {
                var e = document.createEvent("Events");
                e.initEvent(eventName, false, false);
                if (typeof extraArgs != 'undefined') {
                    e.progressVal = extraArgs;
                }
                if (typeof document.dispatchEvent != 'undefined') {
                    document.dispatchEvent(e);
                } else {
                    document.fireEvent(e);
                }
            }
        }
    };
        
}
