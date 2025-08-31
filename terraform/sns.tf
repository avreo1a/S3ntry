resource "aws_sns_topic" "alerts" {
  name = upper(var.project) #S3NTRY
}
