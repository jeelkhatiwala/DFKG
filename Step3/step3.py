import os
import csv
import sys
import hashlib

# Increase CSV field size limit to handle large fields
csv.field_size_limit(sys.maxsize)

# Dictionary mapping package names to human-readable app names (formatted as forensic metadata)
APP_NAMES = {
    "com.android.chrome": "(AN, Google Chrome)",
    "com.android.vending": "(AN, Google Play Store)",
    "com.google.android.apps.docs": "(AN, Google Docs)",
    "com.google.android.apps.maps": "(AN, Google Maps)",
    "com.google.android.apps.photos": "(AN, Google Photos)",
    "com.google.android.apps.restore": "(AN, Google Restore)",
    "com.google.android.apps.tachyon": "(AN, Google Duo)",
    "com.google.android.gm": "(AN, Gmail)",
    "com.google.android.gms": "(AN, Google Play Services)",
    "com.google.android.gms.location.history": "(AN, Google Location History)",
    "com.facebook.appmanager": "(AN, Facebook App Manager)",
    "com.facebook.katana": "(AN, Facebook)",
    "com.facebook.orca": "(AN, Messenger)",
    "com.facebook.services": "(AN, Facebook Services)",
    "com.facebook.system": "(AN, Facebook System)",
    "com.duckduckgo.mobile.android": "(AN, DuckDuckGo Browser)",
    "com.ea.game.nfs14_row": "(AN, Need for Speed)",
    "com.autotrader.android": "(AN, Autotrader)",
    "com.carfax.consumer": "(AN, Carfax)",
    "com.cargurus.mobileApp": "(AN, CarGurus)",
    "com.diotek.sec.lookup.dictionary": "(AN, Dictionary App)",
    "com.google.android.music": "(AN, Google Play Music)",
    "com.google.android.videos": "(AN, Google Play Movies)",
    "com.google.android.youtube": "(AN, YouTube)",
    "com.instagram.android": "(AN, Instagram)",
    "com.lemurmonitors.bluedriver": "(AN, BlueDriver)",
    "com.microsoft.appmanager": "(AN, Microsoft App Manager)",
    "com.microsoft.office.officehubrow": "(AN, Microsoft Office)",
    "com.microsoft.office.outlook": "(AN, Microsoft Outlook)",
    "com.microsoft.skydrive": "(AN, OneDrive)",
    "com.netflix.mediaclient": "(AN, Netflix)",
    "com.netflix.partner.activation": "(AN, Netflix Activation)",
    "com.reddit.frontpage": "(AN, Reddit)",
    "app.cartomizer": "(AN, Cartomizer)",
    "app.greyshirts.sslcapture": "(AN, SSL Capture)",
    "catching.cheatingspouseapp.app": "(AN, Catching Cheating Spouse)",
    "com.androidrocker.voicechanger": "(AN, Voice Changer)",
    "com.antispycell.free": "(AN, Anti Spy Cell)",
    "com.app.tgtg": "(AN, Too Good To Go)",
    "com.beenverified.android": "(AN, BeenVerified)",
    "com.flatfish.cal.privacy": "(AN, Privacy Calculator)",
    "com.gydala.allcars": "(AN, All Cars)",
    "com.hiya.star": "(AN, Hiya)",
    "com.instantcheckmate.app": "(AN, Instant Checkmate)",
    "com.napko.RealDash": "(AN, RealDash)",
    "com.orto.usa": "(AN, Orto)",
    "com.snapchat.android": "(AN, Snapchat)",
    "com.spotify.music": "(AN, Spotify)",
    "com.tmobile.tuesdays": "(AN, T-Mobile Tuesdays)",
    "com.twitter.android": "(AN, Twitter)",
    "com.upside.consumer.android": "(AN, Upside)",
    "com.venmo": "(AN, Venmo)",
    "com.waze": "(AN, Waze)",
    "com.whatsapp": "(AN, WhatsApp)",
    "com.zhiliaoapp.musically": "(AN, TikTok)",
    "org.thoughtcrime.securesms": "(AN, Signal)" 
}

def get_app_name_from_package(package_name):
    """Returns the forensic-formatted app name for a given package name. Defaults to '(AN, Unknown App)' if not found."""
    return APP_NAMES.get(package_name, "(AN, Unknown App)")

def generate_uid(metadata_values):
    """Generates a SHA256 hash UID based on metadata fields and keeps only the first 20 characters."""
    metadata_string = "|".join(metadata_values)  # Concatenate metadata fields with a separator
    uid_hash = hashlib.sha256(metadata_string.encode()).hexdigest()[:15]  # Keep first 20 characters
    return f"(UID, {uid_hash})"

def merge_all_csv_files(base_directory, output_directory, max_rows_per_file=5000, leave_last_rows=500):
    """Merges all CSV files into multiple output files, adding 'UID' and 'AN' as metadata."""

    os.makedirs(output_directory, exist_ok=True)  # Ensure output directory exists

    file_count = 1  # Counter for output files
    row_counter = 0  # Tracks number of rows in the current output file
    output_file = os.path.join(output_directory, f"merged_output_part{file_count}.csv")

    # Open first output file
    out_f = open(output_file, 'w', encoding='utf-8', newline='')
    writer = csv.writer(out_f)

    for root, _, files in os.walk(base_directory):
        if root.endswith("_tables"):  
            for file in files:
                if file.endswith(".csv"):
                    file_path = os.path.join(root, file)

                    try:
                        with open(file_path, 'r', encoding='utf-8') as in_f:
                            reader = csv.reader(in_f)
                            rows = list(reader)

                            if len(rows) < 2:  # Skip empty or header-only CSV files
                                continue

                            # Extract package name from path
                            package_name = root.split(os.sep)[-3]  # Extract package name from directory structure
                            app_name = get_app_name_from_package(package_name)

                            # Extract column names from the first row
                            column_names = rows[0]

                            # Write header in first file
                            if row_counter == 0:
                                writer.writerow(["UID", "AN"] + column_names)  # Add "UID" and "AN" columns first

                            # Skip the first row (column names) and copy row by row
                            for row in rows[1:]:  # Ignore first line
                                if row_counter >= (max_rows_per_file - leave_last_rows):
                                    out_f.close()
                                    file_count += 1
                                    row_counter = 0
                                    output_file = os.path.join(output_directory, f"merged_output_part{file_count}.csv")
                                    out_f = open(output_file, 'w', encoding='utf-8', newline='')
                                    writer = csv.writer(out_f)
                                    writer.writerow(["UID", "AN"] + column_names)  # Add header to new file

                                # Extract metadata values from row
                                metadata_fields = [app_name] + row[:5]  # First 5 columns after AN (usually PID, DN, DP, TN, RL)
                                uid = generate_uid(metadata_fields)  # Generate UID (first 20 characters)

                                writer.writerow([uid, app_name] + row)  # Add UID and AN as the first two columns
                                row_counter += 1

                    except Exception as e:
                        print(f"❌ Error processing {file_path}: {e}")

    out_f.close()
    print(f"\n✅ Merging complete! Created {file_count} output files in: {output_directory}")

# Example Usage:
base_directory = "/home/kali/Desktop/RA/Heisenberg Android/Database/Step2"
output_directory = "/home/kali/Desktop/RA/Heisenberg Android/Database/Step3"

merge_all_csv_files(base_directory, output_directory)


      
