const functions = require("firebase-functions");
const admin = require("firebase-admin");
const { format } = require("date-fns");
const { ptBR } = require("date-fns/locale");

admin.initializeApp();
const db = admin.firestore();

exports.onRequestStatusChange = functions.firestore
  .document("Requests/{requestId}")
  .onUpdate((change, context) => {
    const before = change.before.data();
    const after = change.after.data();
    const requestId = context.params.requestId;

    if (before.Status !== "finished" && after.Status === "finished") {
      const currentTime = format(
        new Date(),
        "dd 'de' MMMM 'de' yyyy 'às' HH:mm:ss 'UTC'XXX",
        { locale: ptBR }
      );

      return db.collection("Requests").doc(requestId).update({
        FinishedAt: currentTime,
      });
    }
    return null;
  });
