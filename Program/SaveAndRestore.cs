using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml.Serialization;

namespace Program {
    public class SaveAndRestore {

        [Serializable]
        public class BreakPoint {
            public ulong Address;
            public string HexAddress;
            public bool ShouldEnable;
            public string Description;
        }

        [Serializable]
        public class BreakPointsList {
            public List<BreakPoint> BreakPoints = new List<BreakPoint>();
            public int Count;
        }

        public class AppState {
            public BreakPointsList BreakPointsListField = new BreakPointsList();
        }

        public static void Save(string fileName, ContextManager cm) {
            var appState = new AppState();
            var bp = appState.BreakPointsListField;

            foreach (var cbp in cm.BreakPoints.Keys) {
                bp.BreakPoints.Add(new BreakPoint {
                    Address = cbp,
                    HexAddress = cbp.ToString("X"),
                    Description = cm.BreakPoints[cbp].Description,
                    ShouldEnable = cm.BreakPoints[cbp].ShouldEnable
                });
            }
            bp.Count = bp.BreakPoints.Count;

            StringBuilder output = new StringBuilder();
            var writer = new StringWriter(output);

            XmlSerializer serializer = new XmlSerializer(typeof(AppState));
            serializer.Serialize(writer, appState);

            using (var sw = new StreamWriter(fileName)) {
                sw.Write(output.ToString());
            }
        }

        public static void Restore(string fileName, ContextManager cm) {
            AppState appState;

            XmlSerializer serializer = new XmlSerializer(typeof(AppState));

            using (StreamReader reader = new StreamReader(fileName)) {
                appState = (AppState)serializer.Deserialize(reader);
                reader.Close();
            }

            foreach (var bp in appState.BreakPointsListField.BreakPoints) {
                cm.AddBreakPoint(bp.Address, new ContextManager.BreakPointInfo {
                    ShouldEnable = bp.ShouldEnable,
                    Description = bp.Description
                });
            }
        }
    }
}