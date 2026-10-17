using System;
using System.IO;
using System.IO.Packaging;
using System.Linq;

// Existing WindowsBase OPC consumer: interpretation evidence, not Microsoft Word fidelity.
public static class OpcConsumer
{
    public static int Main(string[] args)
    {
        if (args.Length != 1 || !Path.IsPathRooted(args[0])) return 2;
        try
        {
            using (Package package = Package.Open(args[0], FileMode.Open, FileAccess.Read))
            {
                var part = package.GetPart(new Uri("/word/document.xml", UriKind.Relative));
                var relationships = part.GetRelationships().ToArray();
                if (relationships.Length != 1) throw new InvalidDataException("case-variant relationship was not recognized exactly once");
                var relation = relationships[0];
                if (relation.Id != "rIdControlled" || relation.TargetMode != TargetMode.Internal ||
                    relation.RelationshipType != "http://schemas.openxmlformats.org/officeDocument/2006/relationships/aFChunk" ||
                    PackUriHelper.ResolvePartUri(part.Uri, relation.TargetUri).OriginalString != "/word/chunk.html")
                    throw new InvalidDataException("independent OPC relationship identity differs");
                Console.WriteLine("OPC_CASE_RELATIONSHIP_RECOGNIZED");
            }
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.GetType().Name + ": " + error.Message);
            return 1;
        }
    }
}
