var config = {
  _id: "rs0",
  members: [
    { _id: 0, host: "mongodb:27017", priority: 10 },
    { _id: 1, host: "mongodb-secondary-1:27017", priority: 1 },
    { _id: 2, host: "mongodb-secondary-2:27017", priority: 1 },
    { _id: 3, host: "mongodb-secondary-3:27017", priority: 1 }
  ]
};

var status = db.adminCommand({ replSetGetStatus: 1 });

if (status.ok) {
  print("Replica set rs0 sudah aktif, tidak perlu inisialisasi ulang");
} else if (status.codeName !== "NotYetInitialized") {
  printjson(status);
  quit(1);
} else {
  var result = rs.initiate(config);
  printjson(result);
  if (!result.ok) quit(1);
  print("Replica set rs0 berhasil dibuat (1 primary + 3 secondary)");
}
