
(function () {
  "use strict";

  function report(api, method) {
    try {
      window.postMessage({
        __pg: true,
        kind: "fingerprint-event",
        api,
        method
      }, "*");
    } catch (_) { /* sandbox restrito */ }
  }

  // ----------------------------------------------------------
  // CANVAS
  // ----------------------------------------------------------
  try {
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function (...args) {
      report("canvas", "toDataURL");
      return origToDataURL.apply(this, args);
    };

    const origToBlob = HTMLCanvasElement.prototype.toBlob;
    if (origToBlob) {
      HTMLCanvasElement.prototype.toBlob = function (...args) {
        report("canvas", "toBlob");
        return origToBlob.apply(this, args);
      };
    }

    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function (...args) {
      report("canvas", "getImageData");
      return origGetImageData.apply(this, args);
    };
  } catch (e) { /* nao quebra a pagina */ }

  // ----------------------------------------------------------
  // WEBGL
  // ----------------------------------------------------------
  function patchWebGL(proto, name) {
    if (!proto) return;
    try {
      const origGetParameter = proto.getParameter;
      proto.getParameter = function (param) {
        // UNMASKED_VENDOR_WEBGL=0x9245  UNMASKED_RENDERER_WEBGL=0x9246
        if (param === 0x9245 || param === 0x9246) {
          report("webgl", `${name}.getParameter(UNMASKED)`);
        } else {
          report("webgl", `${name}.getParameter`);
        }
        return origGetParameter.call(this, param);
      };

      const origGetExtension = proto.getExtension;
      proto.getExtension = function (n) {
        if (typeof n === "string" && /debug_renderer/i.test(n)) {
          report("webgl", `${name}.getExtension(WEBGL_debug_renderer_info)`);
        }
        return origGetExtension.call(this, n);
      };
    } catch (e) { /* ignora */ }
  }
  patchWebGL(window.WebGLRenderingContext && window.WebGLRenderingContext.prototype, "WebGL");
  patchWebGL(window.WebGL2RenderingContext && window.WebGL2RenderingContext.prototype, "WebGL2");

  // ----------------------------------------------------------
  // AUDIOCONTEXT (Web Audio API)
  // ----------------------------------------------------------
  function patchAudio(Ctx) {
    if (!Ctx || !Ctx.prototype) return;
    try {
      const origOsc = Ctx.prototype.createOscillator;
      Ctx.prototype.createOscillator = function (...args) {
        report("audio", "createOscillator");
        return origOsc.apply(this, args);
      };
      const origDyn = Ctx.prototype.createDynamicsCompressor;
      Ctx.prototype.createDynamicsCompressor = function (...args) {
        report("audio", "createDynamicsCompressor");
        return origDyn.apply(this, args);
      };
      const origAnalyser = Ctx.prototype.createAnalyser;
      Ctx.prototype.createAnalyser = function (...args) {
        report("audio", "createAnalyser");
        return origAnalyser.apply(this, args);
      };
    } catch (e) { /* ignora */ }
  }
  patchAudio(window.AudioContext);
  patchAudio(window.OfflineAudioContext);
  patchAudio(window.webkitAudioContext);
  patchAudio(window.webkitOfflineAudioContext);
})();
